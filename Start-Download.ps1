<#PSScriptInfo
.VERSION 1.0.0

.GUID f3d87821-0151-4a7f-bdc8-4d30b1cd6d40

.AUTHOR francisconabas@outlook.com

.COMPANYNAME Frank Nabas Labs

.TAGS Download File Windows Network

.LICENSEURI https://github.com/FranciscoNabas/PowerShellPublic/blob/main/LICENSE

.PROJECTURI https://github.com/FranciscoNabas/PowerShellPublic

.RELEASENOTES
Version 1.0.0:
    - Initial version published.
#>

<#
.SYNOPSIS

    Downloads a file from a URI.

.DESCRIPTION

    This script attempts to download a file from a given URI with progress information.
    The progress outputs the current / total bytes and the average download speed.
    The script attempts to get the file name from the URI. If it contains invalid characters it replaces them with 'a's.
    It implements a cancellation mechanism in case the user hits 'Ctrl + C' or 'Ctrl + Break'.
    If the user cancels or an error occurs during the download we attempt to delete the incomplete file from disk.

.PARAMETER Uri

    The origin URI.

.PARAMETER Destination

    The destination folder. It needs to be an existing directory.
    If this parameter is null the script saves the file in the current directory.

.PARAMETER BufferLength

    The buffer length, or in other words the size of the download 'block'.
    The tradeoff of a big or small buffer size depends on the system and bandwidth.
    Default is 2Mb.

.PARAMETER Force

    If the file already exists it overwrites it.

.EXAMPLE

    Start-Download -Uri 'https://somereliablesite/files/super_file.exe -Destination "$env:USERPROFILE\Downloads"

.EXAMPLE

    Start-Download 'https://somereliablesite/files/super_file.exe -BufferLength 256Kb

.NOTES

    Scripted by: Francisco Nabas
    Scripted on: 2024-10-30
    Version: 1.0.0
    Version date: 2024-10-30

.LINK

    https://github.com/FranciscoNabas
    https://github.com/FranciscoNabas/WindowsUtils
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Uri,

    [Parameter(Position = 1)]
    [ValidateNotNullOrEmpty()]
    [string]$Destination,

    [Parameter()]
    [ValidateRange(1, [int]::MaxValue)]
    [int]$BufferLength = 2048Kb,

    [Parameter()]
    [switch]$Force
)

# Helper types containing the cancellation handler.
Add-Type -TypeDefinition @'
namespace StartDownloadUtilities
{
    using System;
    using System.IO;
    using System.Threading;
    using System.ComponentModel;
    using System.Threading.Tasks;
    using System.Runtime.InteropServices;

    // https://learn.microsoft.com/windows/console/handlerroutine
    public delegate bool HandlerRoutineDelegate(uint dwCtrlType);

    internal static class Console
    {
        // https://learn.microsoft.com/windows/console/setconsolectrlhandler
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetConsoleCtrlHandler(HandlerRoutineDelegate HandlerRoutine, bool Add);

        // Sets a Ctrl handler routine.
        internal static void SetCtrlHandler(HandlerRoutineDelegate handlerRoutine, bool add)
        {
            if (!SetConsoleCtrlHandler(handlerRoutine, add))
                throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public sealed class CancellationHandler : IDisposable
    {
        private readonly string _filePath;
        private readonly FileStream _fileStream;
        private readonly HandlerRoutineDelegate _handler;
        private readonly CancellationTokenSource _tokenSource;

        private bool _isDisposed;

        public CancellationToken Token {
            get { return _tokenSource.Token; }
            private set { }
        }

        // https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-deletefilew
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "DeleteFileW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteFile(string lpFileName);

        public CancellationHandler(string filePath, FileStream fileStream)
        {
            _filePath = filePath;
            _fileStream = fileStream;
            _handler = new HandlerRoutineDelegate(HandleControl);
            _tokenSource = new CancellationTokenSource();
            Console.SetCtrlHandler(_handler, true);
            _isDisposed = false;
        }

        public void Dispose()
        {
            if (!_isDisposed) {
                _fileStream.Dispose();
                _tokenSource.Dispose();
                _isDisposed = true;
                try { Console.SetCtrlHandler(_handler, false); }
                catch { }
            }

            GC.SuppressFinalize(this);
        }

        private bool HandleControl(uint type)
        {
            switch (type) {
                case 0: // CTRL_C_EVENT
                case 1: // CTRL_BREAK_EVENT
                    if (!_isDisposed && !_tokenSource.IsCancellationRequested) {
                        _tokenSource.Cancel();

                        // If the user cancels we try to delete the file, which will be incomplete.
                        // Since the stream needs to flush and write to disk before it closes we call it in a task.
                        // This way we don't hold the console.
                        Task.Run(() => {
                            if (File.Exists(_filePath)) {
                                _fileStream.Close();
                                DeleteFile(_filePath);
                            }
                        });

                        return true;
                    }
                    else
                        return false;
                default:
                    return false;
            }
        }
    }
}
'@

# This function checks if the file name returned from the URI contains any invalid character
# and replaces it with 'a's before combining it to the destination directory and returning.
function Get-ValidFilePathFromUriFileName {

    param([string]$FileName, [string]$Destination)

    # Output buffer and the platform-independent list of invalid file name chars.
    $buffer = [System.Text.StringBuilder]::new($FileName.Length)
    $invalidFileNameChars = [System.IO.Path]::GetInvalidFileNameChars()

    # We explicitly get the enumerator here because PowerShell might box the string.
    $charEnum = $FileName.GetEnumerator()
    try {
        while ($charEnum.MoveNext()) {
            if ($invalidFileNameChars.Contains($charEnum.Current)) {
                [void]$buffer.Append('a')
            }
            else {
                [void]$buffer.Append($charEnum.Current)
            }
        }
    }
    finally {
        $charEnum.Dispose()
    }

    return [System.IO.Path]::Combine($Destination, $buffer.ToString())
}

try {
    # Windows PowerShell doesn't load this assembly by default.
    [void][System.Reflection.Assembly]::LoadWithPartialName('System.Net.Http')

    # Getting the destination path.
    if ($Destination) {
        if (![System.IO.Directory]::Exists($Destination)) {
            throw [System.IO.FileNotFoundException]::new("Could not find directory '$Destination'.")
        }

        $finalDestination = $Destination
    }
    else {
        $currentPathInfo = $PSCmdlet.SessionState.Path.CurrentLocation

        # Checking if the current path is a File System path.
        if ($currentPathInfo.Provider.Name -ne 'FileSystem') {
            throw [ArgumentException]::new("Current location provider '$($currentPathInfo.Provider.Name)' not supported.")
        }

        # Sanity check.
        if (![System.IO.Directory]::Exists($currentPathInfo.Path)) {
            throw [System.IO.FileNotFoundException]::new("Could not find directory '$($currentPathInfo.Path)'.")
        }

        $finalDestination = $currentPathInfo.Path
    }

    # Parsing the URI and getting the destination file name.
    $manUri = [uri]::new($Uri)
    $fileName = [System.IO.Path]::GetFileName($manUri.LocalPath)
    if ([string]::IsNullOrEmpty($fileName)) {
        throw new [ArgumentException]::new('Could not extract file name from URI.')
    }

    $filePath = Get-ValidFilePathFromUriFileName -FileName $fileName -Destination $finalDestination
    if ([System.IO.File]::Exists($filePath)) {
        if (!$Force) {
            throw [ArgumentException]::new("There is already a file named '$fileName' at the destination. To ovewrite it use the 'Force' parameter.")
        }
        else {
            Remove-Item -Path $filePath -Force -ErrorAction Stop
        }
    }

    # Creating the HTTP client, opening the file stream, and creating the cancellation handler.
    # The handler is responsible for closing the file stream at the end or if the user cancels.
    $client = [System.Net.Http.HttpClient]::new()
    $fileStream = [System.IO.File]::Create($filePath)
    $cancellationHandler = [StartDownloadUtilities.CancellationHandler]::new($filePath, $fileStream)

    Write-Progress -Activity "Downloading file '$fileName'" -Status 'Getting content length...' -PercentComplete 0

    # If something fails we delete the destination file.
    $completed = $false

    # Accessing the task 'Result' will block. The poor man's 'await'.
    $response = $client.GetAsync($manUri, 'ResponseHeadersRead', $cancellationHandler.Token).Result
    try { $dataLength = $response.Content.Headers.ContentLength }
    finally { $response.Dispose() }

    # Getting the content stream.
    $stream = $client.GetStreamAsync($manUri).Result

    # Creating a thread-safe messenger so we can record the progress.
    $messenger = [hashtable]::Synchronized(@{ Progress = 0 })

    Write-Progress -Activity "Downloading file '$fileName'" -Status 'Creating download task...' -PercentComplete 0

    # Creating the download task. We do this in a separate task so we don't spend time calculating and writing progress.
    $downloadTask = [powershell]::Create()
    [void]$downloadTask.AddScript({
        param($NetworkStream, $FileStream, $BufferSize, $Messenger, $CancellationToken)

        $buffer = [byte[]]::new($BufferSize)
        do {
            # If the user cancels we ball.
            if ($CancellationToken.IsCancellationRequested) {
                return
            }

            # Reading the stream and writing to the file.
            $bytesRead = $NetworkStream.Read($buffer, 0, $BufferSize)
            if ($bytesRead -gt 0) {
                $FileStream.Write($buffer, 0, $bytesRead)
                $Messenger.Progress += $bytesRead
            }

        } while ($bytesRead -gt 0)

    }).AddParameters(@{
        'NetworkStream'     = $stream                     # The network content stream.
        'FileStream'        = $fileStream                 # The destination file stream.
        'BufferSize'        = $BufferLength               # The buffer size.
        'Messenger'         = $messenger                  # The progress messenger.
        'CancellationToken' = $cancellationHandler.Token  # The cancellation token.
    }).BeginInvoke()

    # The monitoring loop.
    $speedText = '0 B/s'
    $previousProgress = 0
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    do {
        # Checking if the user cancelled.
        if ($cancellationHandler.Token.IsCancellationRequested) {
            break
        }

        # Calculating average speed.
        $elapsedSeconds = $sw.Elapsed.TotalSeconds
        $currentProgress = $messenger.Progress
        if ($elapsedSeconds -gt 1) {

            # Restarting the timer so we don't hold it while calculating the progress.
            $sw.Restart()

            # Average speed in bytes/s.
            $delta = $currentProgress - $previousProgress
            $bytesSecond = $delta / $elapsedSeconds
            $previousProgress = $currentProgress

            # Assembling the speed string based on the average speed.
            switch ($bytesSecond) {
                { $_ -lt 1Kb } { $speedText = "$([Math]::Round($bytesSecond, 2)) B/s" }
                { $_ -ge 1Kb -and $_ -lt 1Mb } { $speedText = "$([Math]::Round($bytesSecond / 1Kb, 2)) Kb/s" }
                { $_ -ge 1Mb -and $_ -lt 1Gb } { $speedText = "$([Math]::Round($bytesSecond / 1Mb, 2)) Mb/s" }
                Default { $speedText = "$([Math]::Round($bytesSecond / 1Gb, 2)) Gb/s" }
            }
        }

        # Writing progress and sleeping to relief the CPU.
        Write-Progress -Activity "Downloading file '$fileName'" -Status "Progress: $currentProgress/$dataLength - $speedText." -PercentComplete (($currentProgress / $dataLength) * 100)
        [System.Threading.Thread]::Sleep(20)

    } while ($downloadTask.InvocationStateInfo.State -eq 'Running')
    Write-Progress -Activity "Downloading file '$fileName'" -Status "Progress: $currentProgress/$dataLength." -Completed

    # Marshaling any errors from the task.
    $hadErrors = $false
    if ($downloadTask.HadErrors -or $downloadTask.Streams.Error -gt 0) {

        # Checking for error records on the error stream.
        if ($downloadTask.Streams.Error -gt 0) {
            foreach ($record in $downloadTask.Streams.Error) {
                Write-Error -ErrorRecord $record
            }
        }
        else {
            # Checking if there is an exception on the reason.
            if ($downloadTask.InvocationStateInfo.Reason) {
                Write-Error -Exception $downloadTask.InvocationStateInfo.Reason
            }
            else {
                throw 'The PowerShell task had errors, but no exception was found.'
            }
        }

        $hadErrors = $true
    }

    # We done.
    $completed = $true
}
finally {
    # Cleaning up resources. The 'if' checks is to avoid having a lot of nested 'try/finally'.
    # Disposing of the cancellation handler closes the file stream.
    if ($cancellationHandler) { $cancellationHandler.Dispose() }
    if ($downloadTask) { $downloadTask.Dispose() }
    if ($stream) { $stream.Dispose() }
    if ($client) { $client.Dispose() }

    # If for some reason we get here with an incomplete download we attempt to delete the file.
    if (!$completed -or $hadErrors) {
        $fileStream.Dispose()
        Remove-Item -Path $filePath -Force -ErrorAction SilentlyContinue
    }
}
