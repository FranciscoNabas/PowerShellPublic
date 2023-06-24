function Get-DownloadAverageTimeAndSpeed {
    [CmdletBinding()]
    param (
        [Parameter(
            Mandatory,
            Position = 0,
            HelpMessage = 'The URL to the file to be donwloaded.'
        )]
        [string]$Url,

        [Parameter(
            Mandatory,
            HelpMessage = 'The donwload method.'
        )]
        [ValidateSet('BITS', 'HttpWebRequest', 'Native')]
        [string]$Method,
    
        [Parameter(
            HelpMessage = 'The number of times the download is made to average.'
        )]
        [ValidateRange(1, 100)]
        [int]$IterationNumber = 3,
    
        [Parameter()]
        [switch]$TestNativeInCSharp
    )
    
    # Function to download a file using the WinHttp native API.
    function Start-NativeDownload {
    
        param($Uri)
    
        # Here we open a WinHttp session, connect to the destination host, and open a request to the file.
        $hSession = [Utilities.WinHttp]::WinHttpOpen('NativeDownload', 0, '', '', 0)
        $hConnect = [Utilities.WinHttp]::WinHttpConnect($hSession, $Uri.Host, 80, 0)
        $hRequest = [Utilities.WinHttp]::WinHttpOpenRequest($hConnect, 'GET', $Uri.AbsolutePath, '', '', '', 0)
        
        # Sending the first request.
        if (![Utilities.WinHttp]::WinHttpSendRequest($hRequest, '', 0, [IntPtr]::Zero, 0, 0, [UIntPtr]::Zero)) {
            Write-Error 'Failed sending request.'
        }
        if (![Utilities.WinHttp]::WinHttpReceiveResponse($hRequest, [IntPtr]::Zero)) {
            Write-Error 'Failed receiving response.'
        }
    
        # Creating the temp file memory stream.
        $tempFilePath = [System.IO.Path]::GetTempFileName()
        $fileStream = New-Object -TypeName 'System.IO.FileStream' -ArgumentList @($tempFilePath, 'Create')
        
        # Reading data until there is no more data available.
        do {
            # Querying if there is data available.
            $dwSize = 0
            if (![Utilities.WinHttp]::WinHttpQueryDataAvailable($hRequest, [ref]$dwSize)) {
                Write-Error 'Failed querying for available data.'
            }
    
            # Allocating memory, and creating the byte array who will hold the managed data.
            $chunk = New-Object -TypeName "System.Byte[]" -ArgumentList $dwSize
            $buffer = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($dwSize)
    
            # Reading the data.
            try {
                if (![Utilities.WinHttp]::WinHttpReadData($hRequest, $buffer, $dwSize, [ref]$dwSize)) {
                    Write-Error 'Failed to read data.'
                }
        
                # Copying the data from the unmanaged pointer to the managed byte array,
                # then writting the data into the file stream.
                [System.Runtime.InteropServices.Marshal]::Copy($buffer, $chunk, 0, $chunk.Length)
                $fileStream.Write($chunk, 0, $chunk.Length)
            }
            finally {
                # Freeing the unmanaged memory.
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($buffer)
            }
    
        } while ($dwSize -gt 0)
    
        # Closing the unmanaged handles.
        [void][Utilities.WinHttp]::WinHttpCloseHandle($hRequest)
        [void][Utilities.WinHttp]::WinHttpCloseHandle($hConnect)
        [void][Utilities.WinHttp]::WinHttpCloseHandle($hSession)
    
        # Disposing of the file stream will close the file handle, which will allow us
        # to manage the file later.
        $fileStream.Dispose()
    
        # Returning the temp file path.
        return $tempFilePath
    }
    
    try {
        Add-Type -TypeDefinition @'
        namespace Utilities
        {
            using System;
            using System.IO;
            using System.Runtime.InteropServices;
        
            [Flags]
            public enum WinHttpFlags : uint
            {
                WINHTTP_FLAG_NONE = 0,
                WINHTTP_FLAG_ASYNC = 0x10000000,
                WINHTTP_FLAG_SECURE_DEFAULTS = 0x30000000,
                WINHTTP_FLAG_SECURE = 0x00800000,
                WINHTTP_FLAG_ESCAPE_PERCENT = 0x00000004,
                WINHTTP_FLAG_NULL_CODEPAGE = 0x00000008,
                WINHTTP_FLAG_ESCAPE_DISABLE = 0x00000040,
                WINHTTP_FLAG_ESCAPE_DISABLE_QUERY = 0x00000080,
                WINHTTP_FLAG_BYPASS_PROXY_CACHE = 0x00000100,
                WINHTTP_FLAG_REFRESH = WINHTTP_FLAG_BYPASS_PROXY_CACHE,
                WINHTTP_FLAG_AUTOMATIC_CHUNKING = 0x00000200
            }
        
            public class WinHttp
            {
                public static readonly uint WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
                public static readonly uint WINHTTP_ACCESS_TYPE_NO_PROXY = 1;
                public static readonly uint WINHTTP_ACCESS_TYPE_NAMED_PROXY = 3;
                public static readonly uint WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4;
        
                [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern IntPtr WinHttpOpen(
                    [MarshalAs(UnmanagedType.LPWStr)] string pszAgentW,
                    uint dwAccessType,
                    [MarshalAs(UnmanagedType.LPWStr)] string pszProxyW,
                    [MarshalAs(UnmanagedType.LPWStr)] string pszProxyBypassW,
                    WinHttpFlags dwFlags
                );
        
                [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern IntPtr WinHttpConnect(
                    IntPtr hSession,
                    string pswzServerName,
                    uint nServerPort,
                    uint dwReserved
                );
        
                [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern IntPtr WinHttpOpenRequest(
                    IntPtr hConnect,
                    string pwszVerb,
                    string pwszObjectName,
                    string pwszVersion,
                    string pwszReferrer,
                    string ppwszAcceptTypes,
                    WinHttpFlags dwFlags
                );
        
                [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool WinHttpSendRequest(
                    IntPtr hRequest,
                    string lpszHeaders,
                    uint dwHeadersLength,
                    IntPtr lpOptional,
                    uint dwOptionalLength,
                    uint dwTotalLength,
                    UIntPtr dwContext
                );
        
                [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool WinHttpReceiveResponse(
                    IntPtr hRequest,
                    IntPtr lpReserved
                );
        
                [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool WinHttpQueryDataAvailable(
                    IntPtr hRequest,
                    out uint lpdwNumberOfBytesAvailable
                );
        
                [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool WinHttpReadData(
                    IntPtr hRequest,
                    IntPtr lpBuffer,
                    uint dwNumberOfBytesToRead,
                    out uint lpdwNumberOfBytesRead
                );
        
                [DllImport("Winhttp.dll", SetLastError = true, CharSet = CharSet.Unicode)]
                public static extern bool WinHttpCloseHandle(IntPtr hInternet);
        
                public static string NativeDownload(Uri uri)
                {
                    IntPtr hInternet = WinHttpOpen("NativeFileDownloader", 0, "", "", 0);
                    if (hInternet == IntPtr.Zero)
                        throw new SystemException($"WinHttpOpen: {Marshal.GetLastWin32Error()}");
        
                    IntPtr hConnect = WinHttpConnect(hInternet, uri.Host, 443, 0);
                    if (hConnect == IntPtr.Zero)
                        throw new SystemException($"WinHttpConnect: {Marshal.GetLastWin32Error()}");
        
                    IntPtr hRequest = WinHttpOpenRequest(hConnect, "GET", uri.AbsolutePath, "", "", "", WinHttpFlags.WINHTTP_FLAG_SECURE);
                    if (hRequest == IntPtr.Zero)
                        throw new SystemException($"WinHttpOpenRequest: {Marshal.GetLastWin32Error()}");
        
                    if (!WinHttpSendRequest(hRequest, "", 0, IntPtr.Zero, 0, 0, UIntPtr.Zero))
                        throw new SystemException($"WinHttpSendRequest: {Marshal.GetLastWin32Error()}");
        
                    if (!WinHttpReceiveResponse(hRequest, IntPtr.Zero))
                        throw new SystemException($"WinHttpReceiveResponse: {Marshal.GetLastWin32Error()}");
        
                    string tempFilePath = Path.GetTempFileName();
                    FileStream fileStream = new FileStream(tempFilePath, FileMode.Create);
                    uint dwBytes;
                    do
                    {
                        if (!WinHttpQueryDataAvailable(hRequest, out dwBytes))
                            throw new SystemException($"WinHttpQueryDataAvailable: {Marshal.GetLastWin32Error()}");
        
                        byte[] chunk = new byte[dwBytes];
                        IntPtr buffer = Marshal.AllocHGlobal((int)dwBytes);
                        try
                        {
                            if (!WinHttpReadData(hRequest, buffer, dwBytes, out _))
                                throw new SystemException($"WinHttpReadData: {Marshal.GetLastWin32Error()}");
                        
                            Marshal.Copy(buffer, chunk, 0, chunk.Length);
                            fileStream.Write(chunk, 0, chunk.Length);
                        }
                        finally
                        {
                            Marshal.FreeHGlobal(buffer);
                        }
                        
                    } while (dwBytes > 0);
        
                    WinHttpCloseHandle(hRequest);
                    WinHttpCloseHandle(hConnect);
                    WinHttpCloseHandle(hInternet);
        
                    fileStream.Dispose();
        
                    return tempFilePath;
                }
            }
        }
'@ -ErrorAction SilentlyContinue
    }
    catch { }
    
    # Defining the file to test, the stopwatch to measure the time, and the timespan to hold the elapsed time average.
    $stopwatch = New-Object -TypeName 'System.Diagnostics.Stopwatch'
    $elapsedTime = [timespan]::Zero
    
    # Creating the URI, and getting the total file size.
    $uri = New-Object -TypeName 'System.Uri' -ArgumentList $Url
    $totalSizeBytes = [System.Net.HttpWebRequest]::Create($uri).GetResponse().ContentLength
    
    # Switching on the Method parameter.
    switch ($Method) {
        'BITS' {
            foreach ($iteration in 1..$IterationNumber) {
                
                # Creating temp file name.
                $tempFilePath = [System.IO.Path]::GetTempFileName()
                
                # Restarting the stopwatch.
                $stopwatch.Restart()
    
                # Starting the BITS transfer.
                Start-BitsTransfer -Source $payloadUrl -Destination $tempFilePath -ProgressAction SilentlyContinue
                
                # Stopping the stopwatch.
                $stopwatch.Stop()
                
                # Deleting the temporary file and storing the elapsed time.
                Remove-Item -Path $tempFilePath
                $elapsedTime = $elapsedTime.Add($stopwatch.Elapsed)
            }
        }
    
        # This method looks very similar to the native one, in terms of steps.
        # That's because this .NET library wraps the same API we're using.
        'HttpWebRequest' {
            foreach ($iteration in 1..$IterationNumber) {
                
                # Creating the web request.
                $request = [System.Net.HttpWebRequest]::Create($uri)
    
                # If necessary you can set the download timeout in milliseconds.
                $request.Timeout = 15000
    
                # Restarting the stopwatch.
                $stopwatch.Restart()
    
                # Receiving the first request, opening a file memory stream, and creating a buffer.
                $responseStream = $request.GetResponse().GetResponseStream()
                $tempFilePath = [System.IO.Path]::GetTempFileName()
                $targetStream = New-Object -TypeName 'System.IO.FileStream' -ArgumentList @($tempFilePath, 'Create')
                $buffer = New-Object 'System.Byte[]' -ArgumentList 10Kb
    
                # Reading data and writting to the file stream, until there is no more data to read.
                do {
                    $count = $responseStream.Read($buffer, 0, $buffer.Length)
                    $targetStream.Write($buffer, 0, $count)
    
                } while ($count -gt 0)
    
                # Stopping the stopwatch, and storing the elapsed time.
                $stopwatch.Stop()
                $elapsedTime = $elapsedTime.Add($stopwatch.Elapsed)
    
                # Disposing of unmanaged resources, and deleting the temp file.
                $targetStream.Dispose()
                $responseStream.Dispose()
                Remove-Item -Path $tempFilePath
            }
        }
    
        'Native' {
            foreach ($iteration in 1..$IterationNumber) {
    
                # Resetting the stopwatch, and downloading the file.
                $stopwatch.Restart()
                if ($Test) {
                    $tempFilePath = [Utilities.WinHttp]::NativeDownload($uri)
                }
                else {
                    $tempFilePath = Start-NativeDownload -Uri $uri
                }
    
                # Stopping the stopwatch, storing the elapsed time, and deleting the temp file.
                $stopwatch.Stop()
                $elapsedTime = $elapsedTime.Add($stopwatch.Elapsed)
                Remove-Item -Path $tempFilePath
            }
        }
    
        # We don't need Default because we are using ValidateSet.
        # Default {
        #    
        # }
    }
    
    # Getting the elapsed time average, and speed in B/s.
    # Timespan.Divide is not available on .NET Framework.
    if ($Host.Version -ge [version]'6.0') { $average = $elapsedTime.Divide($IterationNumber) }
    else { $average = [timespan]::new($elapsedTime.Ticks / $IterationNumber) }
    
    $bytesPerSecond = $totalSizeBytes / $average.TotalSeconds
    
    # Creating the speed text based on size.
    switch ($bytesPerSecond) {
        { $_ -gt 99 } { $finalSpeedText = "$([Math]::Round($bytesPerSecond / 1KB, 2)) Kb/s" }
        { $_ -gt 101376 } { $finalSpeedText = "$([Math]::Round($bytesPerSecond / 1MB, 2)) Mb/s" }
        { $_ -gt 103809024 } { $finalSpeedText = "$([Math]::Round($bytesPerSecond / 1GB, 2)) Gb/s" }
        { $_ -gt 106300440576 } { $finalSpeedText = "$([Math]::Round($bytesPerSecond / 1TB, 2)) Tb/s" } # Why not?
        Default { $finalSpeedText = "$([Math]::Round($bytesPerSecond, 2)) B/s" }
    }
    
    return [PSCustomObject]@{
        Speed    = $finalSpeedText
        TimeSpan = $average
    }
}
