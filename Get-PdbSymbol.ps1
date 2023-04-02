<#
    .SYNOPSIS
    
        Downloads symbols from the Microsoft store.

    .DESCRIPTION

        This function downloads symbols from the Microsoft store.
        It is based on the PDB-Downloader application.
        It was optimized to run in a console with huge file lists.

    .PARAMETER Path

        The path(s) to the image we want to donwload the symbol.

    .PARAMETER DestinationStore

        The path where we want to store the symbols.
        Default value is 'C:\Symbols'.

    .EXAMPLE

        PS C:\>_ [string[]]$fileList = (Get-ChildItem -Path 'C:\Windows\System32' -Recurse -Force -File | Where-Object {
            ($PSItem.Name -like '*.exe') -or ($PSItem.Name -like '*.dll')
        }).FullName
        
        PS C:\>_ Get-PdbSymbol -Path $fileList -DestinationStore 'C:\Symbols'

    .NOTES

        This script is provided under the MIT license.
        Version: 1.0.0
        Release date: 31-03-2023
        Author: Francisco Nabas

    .LINK

        https://github.com/rajkumar-rangaraj/PDB-Downloader
        https://learn.microsoft.com/en-us/archive/blogs/webtopics/pdb-downloader
        https://github.com/FranciscoNabas
#>

<#
    TODO: There is something under '$env:SystemRoot\SysWOW64' that freezes the byte reading.
    I tried this function in about 31000 files (everything under $env:SystemRoot).
    Maybe the images are too big? Something is not being disposed correctly in the loop?
    NO ONE KNOWS.
#>

function Get-PdbSymbol {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory, Position = 0)]
        [string[]]$Path,

        [Parameter(Position = 1)]
        [string]$DestinationStore = 'C:\Symbols'
    )

    #Requires -Version 7.3

    Begin {

        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')

        # https://stackoverflow.com/questions/21422364/is-there-any-way-to-monitor-the-progress-of-a-download-using-a-webclient-object
        function Invoke-FileDownloadWithProgress($Url, $TargetFile, $ParentProgressBarId = -1) {
            $uri = New-Object "System.Uri" "$Url"
            $request = [System.Net.HttpWebRequest]::Create($uri)
            $request.set_Timeout(15000) #15 second timeout
    
            try {
                $response = $request.GetResponse()
                $totalLength = [System.Math]::Floor($response.get_ContentLength() / 1024)
                $responseStream = $response.GetResponseStream()
                $targetStream = New-Object -TypeName System.IO.FileStream -ArgumentList $TargetFile, Create
                $buffer = new-object byte[] 10KB
                $count = $responseStream.Read($buffer, 0, $buffer.length)
                $downloadedBytes = $count
    
                while ($count -gt 0) {

                    $targetStream.Write($buffer, 0, $count)
                    $count = $responseStream.Read($buffer, 0, $buffer.length)
                    $downloadedBytes = $downloadedBytes + $count
                    Write-Progress -Id ($ParentProgressBarId + 1) -ParentId $ParentProgressBarId -Activity "Downloading file '$($Url.split('/') | Select-Object -Last 1)'" -Status "Downloaded ($([System.Math]::Floor($downloadedBytes/1024))K of $($totalLength)K): " -PercentComplete ((([System.Math]::Floor($downloadedBytes / 1024)) / $totalLength) * 100)
                    if ([System.Math]::Floor($downloadedBytes / 1024) -eq $totalLength) {
                        break
                    }
                }
            }
            catch {
                throw $PSItem
            }
            finally {
                if ($targetStream) {
                    $targetStream.Flush()
                    $targetStream.Dispose()
                }
                if ($responseStream) { $responseStream.Dispose() }
            }
        }

        function Get-ObjectFromStreamBytes([System.IO.BinaryReader]$Reader, [type]$Type) {

            try {
                $bytes = $Reader.ReadBytes([System.Runtime.InteropServices.Marshal]::SizeOf(([type]$Type)))
                if ($bytes.Count -gt 0) {

                    # Technically we don't need to pin the address of 'bytes' because 'PtrToStructure' is going to copy the data before it goes out of scope. Maybe?
                    $hBytes = [System.Runtime.InteropServices.Marshal]::UnsafeAddrOfPinnedArrayElement($bytes, 0)
                    return [System.Runtime.InteropServices.Marshal]::PtrToStructure($hBytes, ([type]$Type))
                }
            }
            catch {
                if ($PSItem.Exception.InnerException.GetType() -ne [System.ObjectDisposedException]) {
                    throw $PSItem
                }
            }
        }

        function Invoke-StreamSeek($Stream, $Offset, $Origin) {
            
            try {
                [void]$Stream.Seek($Offset, $Origin)
            }
            catch {
                if ($PSItem.Exception.InnerException.GetType() -ne [System.ObjectDisposedException]) {
                    throw $PSItem
                }
            }
        }
    }

    Process {
        try {

            ## Naive structures to read binary debug information.
            Add-Type -TypeDefinition @'
            using System;
            using System.Runtime.InteropServices;
                    
            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DOS_HEADER
            {      
                public UInt16 e_magic;              // Magic number
                public UInt16 e_cblp;               // Bytes on last page of file
                public UInt16 e_cp;                 // Pages in file
                public UInt16 e_crlc;               // Relocations
                public UInt16 e_cparhdr;            // Size of header in paragraphs
                public UInt16 e_minalloc;           // Minimum extra paragraphs needed
                public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
                public UInt16 e_ss;                 // Initial (relative) SS value
                public UInt16 e_sp;                 // Initial SP value
                public UInt16 e_csum;               // Checksum
                public UInt16 e_ip;                 // Initial IP value
                public UInt16 e_cs;                 // Initial (relative) CS value
                public UInt16 e_lfarlc;             // File address of relocation table
                public UInt16 e_ovno;               // Overlay number
                public UInt16 e_res_0;              // Reserved words
                public UInt16 e_res_1;              // Reserved words
                public UInt16 e_res_2;              // Reserved words
                public UInt16 e_res_3;              // Reserved words
                public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
                public UInt16 e_oeminfo;            // OEM information; e_oemid specific
                public UInt16 e_res2_0;             // Reserved words
                public UInt16 e_res2_1;             // Reserved words
                public UInt16 e_res2_2;             // Reserved words
                public UInt16 e_res2_3;             // Reserved words
                public UInt16 e_res2_4;             // Reserved words
                public UInt16 e_res2_5;             // Reserved words
                public UInt16 e_res2_6;             // Reserved words
                public UInt16 e_res2_7;             // Reserved words
                public UInt16 e_res2_8;             // Reserved words
                public UInt16 e_res2_9;             // Reserved words
                public UInt32 e_lfanew;             // File address of new exe header
            }
            [StructLayout(LayoutKind.Sequential)]
            public struct IMAGE_DATA_DIRECTORY
            {
                public UInt32 VirtualAddress;
                public UInt32 Size;
            }
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER32
            {
                public UInt16 Magic;
                public Byte MajorLinkerVersion;
                public Byte MinorLinkerVersion;
                public UInt32 SizeOfCode;
                public UInt32 SizeOfInitializedData;
                public UInt32 SizeOfUninitializedData;
                public UInt32 AddressOfEntryPoint;
                public UInt32 BaseOfCode;
                public UInt32 BaseOfData;
                public UInt32 ImageBase;
                public UInt32 SectionAlignment;
                public UInt32 FileAlignment;
                public UInt16 MajorOperatingSystemVersion;
                public UInt16 MinorOperatingSystemVersion;
                public UInt16 MajorImageVersion;
                public UInt16 MinorImageVersion;
                public UInt16 MajorSubsystemVersion;
                public UInt16 MinorSubsystemVersion;
                public UInt32 Win32VersionValue;
                public UInt32 SizeOfImage;
                public UInt32 SizeOfHeaders;
                public UInt32 CheckSum;
                public UInt16 Subsystem;
                public UInt16 DllCharacteristics;
                public UInt32 SizeOfStackReserve;
                public UInt32 SizeOfStackCommit;
                public UInt32 SizeOfHeapReserve;
                public UInt32 SizeOfHeapCommit;
                public UInt32 LoaderFlags;
                public UInt32 NumberOfRvaAndSizes;
                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_OPTIONAL_HEADER64
            {
                public UInt16 Magic;
                public Byte MajorLinkerVersion;
                public Byte MinorLinkerVersion;
                public UInt32 SizeOfCode;
                public UInt32 SizeOfInitializedData;
                public UInt32 SizeOfUninitializedData;
                public UInt32 AddressOfEntryPoint;
                public UInt32 BaseOfCode;
                public UInt64 ImageBase;
                public UInt32 SectionAlignment;
                public UInt32 FileAlignment;
                public UInt16 MajorOperatingSystemVersion;
                public UInt16 MinorOperatingSystemVersion;
                public UInt16 MajorImageVersion;
                public UInt16 MinorImageVersion;
                public UInt16 MajorSubsystemVersion;
                public UInt16 MinorSubsystemVersion;
                public UInt32 Win32VersionValue;
                public UInt32 SizeOfImage;
                public UInt32 SizeOfHeaders;
                public UInt32 CheckSum;
                public UInt16 Subsystem;
                public UInt16 DllCharacteristics;
                public UInt64 SizeOfStackReserve;
                public UInt64 SizeOfStackCommit;
                public UInt64 SizeOfHeapReserve;
                public UInt64 SizeOfHeapCommit;
                public UInt32 LoaderFlags;
                public UInt32 NumberOfRvaAndSizes;
                public IMAGE_DATA_DIRECTORY ExportTable;
                public IMAGE_DATA_DIRECTORY ImportTable;
                public IMAGE_DATA_DIRECTORY ResourceTable;
                public IMAGE_DATA_DIRECTORY ExceptionTable;
                public IMAGE_DATA_DIRECTORY CertificateTable;
                public IMAGE_DATA_DIRECTORY BaseRelocationTable;
                public IMAGE_DATA_DIRECTORY Debug;
                public IMAGE_DATA_DIRECTORY Architecture;
                public IMAGE_DATA_DIRECTORY GlobalPtr;
                public IMAGE_DATA_DIRECTORY TLSTable;
                public IMAGE_DATA_DIRECTORY LoadConfigTable;
                public IMAGE_DATA_DIRECTORY BoundImport;
                public IMAGE_DATA_DIRECTORY IAT;
                public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
                public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
                public IMAGE_DATA_DIRECTORY Reserved;
            }
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_FILE_HEADER
            {
                public UInt16 Machine;
                public UInt16 NumberOfSections;
                public UInt32 TimeDateStamp;
                public UInt32 PointerToSymbolTable;
                public UInt32 NumberOfSymbols;
                public UInt16 SizeOfOptionalHeader;
                public UInt16 Characteristics;
            }
            [StructLayout(LayoutKind.Explicit)]
            public struct IMAGE_SECTION_HEADER
            {
                [FieldOffset(0)]
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                public char[] Name;
                [FieldOffset(8)]
                public UInt32 VirtualSize;
                [FieldOffset(12)]
                public UInt32 VirtualAddress;
                [FieldOffset(16)]
                public UInt32 SizeOfRawData;
                [FieldOffset(20)]
                public UInt32 PointerToRawData;
                [FieldOffset(24)]
                public UInt32 PointerToRelocations;
                [FieldOffset(28)]
                public UInt32 PointerToLinenumbers;
                [FieldOffset(32)]
                public UInt16 NumberOfRelocations;
                [FieldOffset(34)]
                public UInt16 NumberOfLinenumbers;
                [FieldOffset(36)]
                public DataSectionFlags Characteristics;
                public string Section
                {
                    get { return new string(Name); }
                }
            }
            [Flags]
            public enum DataSectionFlags : uint
            {
                
                TypeReg = 0x00000000,
                TypeDsect = 0x00000001,
                TypeNoLoad = 0x00000002,
                TypeGroup = 0x00000004,
                TypeNoPadded = 0x00000008,
                TypeCopy = 0x00000010,
                ContentCode = 0x00000020,
                ContentInitializedData = 0x00000040,
                ContentUninitializedData = 0x00000080,
                LinkOther = 0x00000100,
                LinkInfo = 0x00000200,
                TypeOver = 0x00000400,
                LinkRemove = 0x00000800,
                LinkComDat = 0x00001000,
                NoDeferSpecExceptions = 0x00004000,
                RelativeGP = 0x00008000,
                MemPurgeable = 0x00020000,
                Memory16Bit = 0x00020000,
                MemoryLocked = 0x00040000,
                MemoryPreload = 0x00080000,
                Align1Bytes = 0x00100000,
                Align2Bytes = 0x00200000,
                Align4Bytes = 0x00300000,
                Align8Bytes = 0x00400000,
                Align16Bytes = 0x00500000,
                Align32Bytes = 0x00600000,
                Align64Bytes = 0x00700000,
                Align128Bytes = 0x00800000,
                Align256Bytes = 0x00900000,
                Align512Bytes = 0x00A00000,
                Align1024Bytes = 0x00B00000,
                Align2048Bytes = 0x00C00000,
                Align4096Bytes = 0x00D00000,
                Align8192Bytes = 0x00E00000,
                LinkExtendedRelocationOverflow = 0x01000000,
                MemoryDiscardable = 0x02000000,
                MemoryNotCached = 0x04000000,
                MemoryNotPaged = 0x08000000,
                MemoryShared = 0x10000000,
                MemoryExecute = 0x20000000,
                MemoryRead = 0x40000000,
                MemoryWrite = 0x80000000
            }
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_DEBUG_DIRECTORY
            {
                public UInt32 Characteristics;
                public UInt32 TimeDateStamp;
                public UInt16 MajorVersion;
                public UInt16 MinorVersion;
                public UInt32 Type;
                public UInt32 SizeOfData;
                public UInt32 AddressOfRawData;
                public UInt32 PointerToRawData;
            }
            [StructLayout(LayoutKind.Sequential, Pack = 1)]
            public struct IMAGE_DEBUG_DIRECTORY_RAW
            {
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
                public char[] format;
                public Guid guid;
                public uint age;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 255)]
                public char[] name;
            }
'@     
        }
        catch { }
        
        $gciSplat = @{
            Path        = $DestinationStore
            ErrorAction = 'SilentlyContinue'
            Recurse     = [switch]::Present
            Force       = [switch]::Present
            File        = [switch]::Present
        }
        [System.Collections.Generic.HashSet[string]]$existingFilenames = (Get-ChildItem @gciSplat).BaseName
        if (!$existingFilenames) { $existingFilenames = [System.Collections.Generic.HashSet[string]]::new() }

        [System.Collections.Generic.HashSet[string]]$failedFileNames = Get-Content -Path "$DestinationStore\.GetPdbSyFailedCache.log" -ErrorAction SilentlyContinue
        if (!$failedFileNames) { $failedFileNames = [System.Collections.Generic.HashSet[string]]::new() }
        
        $cacheWriter = [System.IO.File]::AppendText("$DestinationStore\.GetPdbSyFailedCache.log")
    
        $processedFileCount = 1
        foreach ($file in $Path) {
            
            Write-Progress -Id 1 -Activity 'Downloading Symbols' -Status "Processed files: $processedFileCount/$($Path.Count). $file" -PercentComplete (($processedFileCount / $Path.Count) * 100)

            if ($existingFilenames.Contains([System.IO.Path]::GetFileNameWithoutExtension($file)) -or $failedFileNames.Contains($file)) {
                Write-Progress -Id 1 -Activity 'Downloading Symbols' -Status "Processed files: $processedFileCount/$($Path.Count)" -PercentComplete (($processedFileCount / $Path.Count) * 100)
                $processedFileCount++
                continue
            }
    
            try {
                $fileStream = [System.IO.FileStream]::new($file, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)
                $reader = [System.IO.BinaryReader]::new($fileStream, [System.Text.Encoding]::UTF8)    
            }
            # Not good, I know.
            catch { continue }
            
            $dosHeader = Get-ObjectFromStreamBytes -Reader $reader -Type ([type][IMAGE_DOS_HEADER])
            
            Invoke-StreamSeek -Stream $fileStream -Offset $dosHeader.e_lfanew -Origin ([System.IO.SeekOrigin]::Begin)
            try { [void]$reader.ReadUInt32() }
            # Not good, I know.
            catch { continue }
            
            $fileHeader = Get-ObjectFromStreamBytes -Reader $reader -Type ([type][IMAGE_FILE_HEADER])
            $optHeader = Get-ObjectFromStreamBytes -Reader $reader -Type ([type][IMAGE_OPTIONAL_HEADER64])

            $offDebug = 0
            $cbFromHeader = 0
            $loopExit = 0
            $cbDebug = $optHeader.Debug.Size
            $imgSecHeader = [IMAGE_SECTION_HEADER[]]::new($fileHeader.NumberOfSections)
            
            for ($headerNo = 0; $headerNo -lt $imgSecHeader.Length; $headerNo++) {
                
                $imgSecHeader[$headerNo] = Get-ObjectFromStreamBytes -Reader $reader -Type ([type][IMAGE_SECTION_HEADER])

                if (($imgSecHeader[$headerNo].PointerToRawData -ne 0) -and ($imgSecHeader[$headerNo].SizeOfRawData -ne 0) -and ($cbFromHeader -lt ($imgSecHeader[$headerNo].PointerToRawData + $imgSecHeader[$headerNo].SizeOfRawData))) {
                    $cbFromHeader = ($imgSecHeader[$headerNo].PointerToRawData + $imgSecHeader[$headerNo].SizeOfRawData)
                }
            
                if ($cbDebug -ne 0) {
                    if (($imgSecHeader[$headerNo].VirtualAddress -le $optHeader.Debug.VirtualAddress) -and (($imgSecHeader[$headerNo].VirtualAddress + $imgSecHeader[$headerNo].SizeOfRawData -gt $imgSecHeader[$headerNo].PointerToRawData))) {
                        $offDebug = $optHeader.Debug.VirtualAddress - $imgSecHeader[$headerNo].VirtualAddress + $imgSecHeader[$headerNo].PointerToRawData
                    }
                }
            
            }
            
            Invoke-StreamSeek -Stream $fileStream -Offset $offDebug -Origin ([System.IO.SeekOrigin]::Begin)
            
            while ($cbDebug -ge [System.Runtime.InteropServices.Marshal]::SizeOf([type][IMAGE_DEBUG_DIRECTORY])) {
                if ($loopExit -eq 0) {
                    
                    $imgDebugDir = Get-ObjectFromStreamBytes -Reader $reader -Type ([type][IMAGE_DEBUG_DIRECTORY])
                    
                    $seekPosition = $fileStream.Position
            
                    if ($imgDebugDir.Type -eq 2) {
                        
                        Invoke-StreamSeek -Stream $fileStream -Offset $imgDebugDir.PointerToRawData -Origin ([System.IO.SeekOrigin]::Begin)
                        $debugInfo = Get-ObjectFromStreamBytes -Reader $reader -Type ([type][IMAGE_DEBUG_DIRECTORY_RAW])
                        
                        $loopExit = 1
                        if ([string]::new($debugInfo.name).Contains('.ni.')) {
                            Invoke-StreamSeek -Stream $fileStream -Offset $seekPosition -Origin ([System.IO.SeekOrigin]::Begin)
                            $loopExit = 0
                        }
                    }
            
                    if (($imgDebugDir.PointerToRawData -ne 0) -and ($imgDebugDir.SizeOfData -ne 0) -and ($cbFromHeader -lt ($imgDebugDir.PointerToRawData + $imgDebugDir.SizeOfData))) {
                        $cbFromHeader = $imgDebugDir.PointerToRawData + $imgDebugDir.SizeOfData
                    }
                }
            
                $cbDebug -= [System.Runtime.InteropServices.Marshal]::SizeOf([type][IMAGE_DEBUG_DIRECTORY])
            }
            
            $pdbName = [string]::new($debugInfo.name)
            if (![string]::IsNullOrEmpty($pdbName)) {
                $pdbName = $pdbName.Remove(($pdbName | Select-String -Pattern '\0').Matches[0].Index).Split('\')[$pdbName.Split('\').Length - 1]
                $pdbAge = $debugInfo.age.ToString('X')
                
                $destinationPath = "$DestinationStore\$pdbName\$($debugInfo.guid.ToString('N').ToUpper())$pdbAge"
                
                if (!(Test-Path -Path "$destinationPath\$pdbName" -PathType Leaf)) {
                    if (!(Test-Path -Path $destinationPath -PathType Container)) {
                        [void](mkdir $destinationPath)
                    }
                    $downloadUrl = "http://msdl.microsoft.com/download/symbols/$pdbName/$($debugInfo.guid.ToString('N').ToUpper())$pdbAge/$pdbName"
                    
                    try {
                        Invoke-FileDownloadWithProgress -Url $downloadUrl -TargetFile "$destinationPath\$pdbName" -ParentProgressBarId 1
                    }
                    catch {
                        if ($PSItem.Exception.InnerException.Message -like '*404*') {
                            Remove-Item -Path $destinationPath -Force -ErrorAction SilentlyContinue
                            [void]$cacheWriter.WriteAsync("$file`n")
                        }
                    }
                }

                $fileStream.Flush()
                $fileStream.Dispose() 
                $reader.Dispose()
                
                $processedFileCount++
            }
        }
    }

    Clean {
        $cacheWriter.Dispose()
    }
}
