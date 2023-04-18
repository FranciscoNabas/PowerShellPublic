function Copy-File {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string]$Path,

        [Parameter(Mandatory, Position = 1)]
        [string]$Destination
    )

    $signature = @'
    namespace Utilities {

        using System;
        using System.Runtime.InteropServices;
    
        public class FileSystem {
            
            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool CopyFileEx(
                string lpExistingFileName,
                string lpNewFileName,
                CopyProgressRoutine lpProgressRoutine,
                IntPtr lpData,
                ref Int32 pbCancel,
                CopyFileFlags dwCopyFlags
            );
        
            delegate CopyProgressResult CopyProgressRoutine(
            long TotalFileSize,
            long TotalBytesTransferred,
            long StreamSize,
            long StreamBytesTransferred,
            uint dwStreamNumber,
            CopyProgressCallbackReason dwCallbackReason,
            IntPtr hSourceFile,
            IntPtr hDestinationFile,
            IntPtr lpData);
        
            int pbCancel;
        
            public enum CopyProgressResult : uint
            {
                PROGRESS_CONTINUE = 0,
                PROGRESS_CANCEL = 1,
                PROGRESS_STOP = 2,
                PROGRESS_QUIET = 3
            }
        
            public enum CopyProgressCallbackReason : uint
            {
                CALLBACK_CHUNK_FINISHED = 0x00000000,
                CALLBACK_STREAM_SWITCH = 0x00000001
            }
        
            [Flags]
            enum CopyFileFlags : uint
            {
                COPY_FILE_FAIL_IF_EXISTS = 0x00000001,
                COPY_FILE_RESTARTABLE = 0x00000002,
                COPY_FILE_OPEN_SOURCE_FOR_WRITE = 0x00000004,
                COPY_FILE_ALLOW_DECRYPTED_DESTINATION = 0x00000008
            }
        
            public void CopyWithProgress(string oldFile, string newFile, Func<long, long, long, long, uint, CopyProgressCallbackReason, System.IntPtr, System.IntPtr, System.IntPtr, CopyProgressResult> callback)
            {
                CopyFileEx(oldFile, newFile, new CopyProgressRoutine(callback), IntPtr.Zero, ref pbCancel, CopyFileFlags.COPY_FILE_RESTARTABLE);
            }
        }
    }
'@

    Add-Type -TypeDefinition $signature

    [Func[long, long, long, long, System.UInt32, Utilities.FileSystem+CopyProgressCallbackReason, System.IntPtr, System.IntPtr, System.IntPtr, Utilities.FileSystem+CopyProgressResult]]$copyProgressDelegate = {

        param($total, $transfered, $streamSize, $streamByteTrans, $dwStreamNumber, $reason, $hSourceFile, $hDestinationFile, $lpData)

        Write-Progress -Activity "Copying file" -Status "$Path ~> $Destination. $([Math]::Round(($transfered/1KB), 2))KB/$([Math]::Round(($total/1KB), 2))KB." -PercentComplete (($transfered / $total) * 100)
    }

    $fileName = [System.IO.Path]::GetFileName($Path)
    $destFileName = [System.IO.Path]::GetFileName($Destination)
    if ([string]::IsNullOrEmpty($destFileName) -or $destFileName -notlike '*.*') {
        if ($Destination.EndsWith('\')) {
            $destFullName = "$Destination$fileName"
        }
        else {
            $destFullName = "$Destination\$fileName"
        }
    }

    $wrapper = New-Object Utilities.FileSystem
    $wrapper.CopyWithProgress($Path, $destFullName, $copyProgressDelegate)
}
