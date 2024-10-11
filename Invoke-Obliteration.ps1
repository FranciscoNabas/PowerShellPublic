<#PSScriptInfo
.VERSION 1.0.0

.GUID dcb430bf-7683-41f0-a17d-d64fabd18e6e

.AUTHOR francisconabas@outlook.com

.COMPANYNAME Frank Nabas Labs

.TAGS Remove Remove Delete Files Folders PowerShell Microsoft Windows Explorer

.LICENSEURI https://github.com/FranciscoNabas/PowerShellPublic/blob/main/LICENSE

.PROJECTURI https://github.com/FranciscoNabas/PowerShellPublic
#>

#Requires -RunAsAdministrator

<#
.SYNOPSIS

    Obliterates one or more directories.

.DESCRIPTION

    This function deletes one or more directories recursively, including its files and sub-directories.
    If one of the file system objects are open in another process it attempts to close the handles.
    It was designed to be fast, so we had to use partially undocumented Windows APIs and .NET asynchronous primitives.
    For this reason all logic, except the monitoring, was written in C#. That's why the huge signature.
    The closing handle mechanism was ported from the 'WindowsUtils' module.

    ATTENTION!!!

    This function deletes files and potentially closes open handles without prompting for confirmation!
    It was designed to be like that, simple, fast, and deadly.
    Closing other processe's handles to a file system object may cause system malfunction. Use it with care!

    About privileges:
    This function requires to be ran as administrator, because it needs access to delete files potentially in protected places.
    The main API enables the 'SeBackupPrivilege' and 'SeRestorePrivilege' for the executing process token during execution to make sure we have the right permissions.
    These privileges are disabled once the method ends.

    About cancellation:
    The main API implements a cancellation handler to capture 'Ctrl-C' and 'Ctrl-Break' commands.
    All the internal APIs were designed with cooperative multitasking in mind, so if you press a cancellation combination the operation stops.
    Due some bugs I found with Windows PowerShell I couldn't remove the handler at the end of execution because it breaks the console.
    Although the handle continues registered it does nothing if it's not in the method execution 'context'.

.PARAMETER Path

    One or more file system object paths.

.PARAMETER LiteralPath

    One or more file system object literal paths (PSPath).

.EXAMPLE

    Invoke-Obliteration -Path 'C:\SomeFolderIReallyHate'

.EXAMPLE

    obliterate 'C:\SomeFolderIReallyHate', 'C:\IHateThisOtherOneToo'

.EXAMPLE

    Invoke-Obliteration 'C:\SomeFolder*'

.EXAMPLE

    Get-ChildItem -Path 'C:\SomeFolder' | obliterate

.INPUTS

    A string array of file system object paths.

.OUTPUTS

    A 'Utilities.DeleteFileErrorInfo' is return for every object we fail to delete.
    If no object fails to delete this function returns nothing.

.NOTES

    Scripted by: Francisco Nabas
    Scripted on: 2024-10-09
    Version: 1.0.0
    Version date: 2024-10-09

.LINK

    https://github.com/FranciscoNabas
    https://github.com/FranciscoNabas/WindowsUtils
#>

[CmdletBinding(DefaultParameterSetName = 'byPath')]
[Alias('obliterate')]
[OutputType('DeleteFileErrorInfo')]
param (
    [Parameter(
        Mandatory,
        Position = 0,
        ValueFromPipeline = $true,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'byPath'
    )]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path,

    [Parameter(
        Mandatory,
        ValueFromPipeline = $false,
        ValueFromPipelineByPropertyName = $true,
        ParameterSetName = 'byLiteralPath'
    )]
    [Alias('PSPath')]
    [ValidateNotNullOrEmpty()]
    [string[]]$LiteralPath
)

Begin {
    $theThing = @'
namespace Utilities
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using System.Collections.Generic;
    using System.Collections.Concurrent;
    using System.Runtime.InteropServices;
    using Microsoft.Win32.SafeHandles;

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING
    {
        private readonly ushort Length;
        private readonly ushort MaximumLength;
        private readonly IntPtr Buffer;

        internal string String { get { return Marshal.PtrToStringUni(Buffer, Length / 2); } }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct IO_STATUS_BLOCK
    {
        internal IO_STATUS_BLOCK_Union Union;
        internal IntPtr Information;

        [StructLayout(LayoutKind.Explicit)]
        internal struct IO_STATUS_BLOCK_Union
        {
            [FieldOffset(0)] internal int Status;
            [FieldOffset(0)] internal IntPtr Pointer;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct FILE_FULL_DIR_INFORMATION
    {
        internal int NextEntryOffset;
        internal uint FileIndex;
        internal long CreationTime;
        internal long LastAccessTime;
        internal long LastWriteTime;
        internal long ChangeTime;
        internal long EndOfFile;
        internal long AllocationSize;
        internal uint FileAttributes;
        internal int FileNameLength;
        internal int EaSize;
        private char _fileName;

        internal string FileName { get { return GetName(); } }

        private unsafe string GetName()
        {
            fixed (char* namePtr = &_fileName) {
                return new string(namePtr, 0, FileNameLength / 2);
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_PROCESS_IDS_USING_FILE_INFORMATION
    {
        internal uint NumberOfProcessIdsInList;
        private UIntPtr _processIdList;

        internal int[] ProcessIdList { get { return GetProcessIdList(); } }

        private unsafe int[] GetProcessIdList()
        {
            int[] output = new int[NumberOfProcessIdsInList];
            fixed (UIntPtr* listPtr = &_processIdList) {
                for (int i = 0; i < NumberOfProcessIdsInList; i++) {
                    output[i] = (int)listPtr[i];
                }
            }

            return output;
        }
    }

    // This structure has more members, but we only care aboud the handle value.
    [StructLayout(LayoutKind.Sequential, Size = 40, Pack = 8)]
    internal struct PROCESS_HANDLE_TABLE_ENTRY_INFO
    {
        internal IntPtr HandleValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_HANDLE_SNAPSHOT_INFORMATION
    {
        internal UIntPtr NumberOfHandles;
        internal UIntPtr Reserved;
        private PROCESS_HANDLE_TABLE_ENTRY_INFO _handles;

        public PROCESS_HANDLE_TABLE_ENTRY_INFO[] Handles { get { return GetHandleTable(); } }

        private unsafe PROCESS_HANDLE_TABLE_ENTRY_INFO[] GetHandleTable()
        {
            PROCESS_HANDLE_TABLE_ENTRY_INFO[] output = new PROCESS_HANDLE_TABLE_ENTRY_INFO[(long)NumberOfHandles];
            fixed (PROCESS_HANDLE_TABLE_ENTRY_INFO* tablePtr = &_handles) {
                for (long i = 0; i < (long)NumberOfHandles; i++) {
                    output[i] = tablePtr[i];
                }
            }

            return output;
        }
    }

    // This structure has more members, but we only care aboud the type name.
    [StructLayout(LayoutKind.Sequential, Size = 100, Pack = 4)]
    internal struct OBJECT_TYPE_INFORMATION
    {
        internal UNICODE_STRING TypeName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_NAME_INFORMATION
    {
        internal UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        internal uint LowPart;
        internal int HighPart;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct LUID_AND_ATTRIBUTES
    {
        internal LUID Luid;
        internal uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        internal uint PrivilegeCount;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        internal LUID_AND_ATTRIBUTES[] Privileges;
    }

    // This object is returned by the main API for files we fail to delete.
    public sealed class DeleteFileErrorInfo
    {
        public string FilePath { get; private set; }
        public Exception Exception { get; internal set; }

        internal DeleteFileErrorInfo(string path, Exception exception)
        {
            this.FilePath = path;
            this.Exception = exception;
        }
    }

    // Main class.
    public sealed class Obliterator
    {
        // Main API. Deletes files and directories recursively, closing open handles and storing progress.
        public static DeleteFileErrorInfo[] Obliterate(string[] pathList, ConcurrentDictionary<string, int> progressMonitor, ConcurrentBag<Tuple<string, int>> closedHandlesMonitor)
        {
            bool isTokenValid = false;
            ConcurrentBag<DeleteFileErrorInfo> errorList = new ConcurrentBag<DeleteFileErrorInfo>();

            // Creating the cancellation token source.
            using (CancellationTokenSource tokenSource = new CancellationTokenSource()) {
                isTokenValid = true;

                // Registering the Ctrl + C handler.
                Console.CancelKeyPress += (sender, args) => {
                    if (isTokenValid && !tokenSource.IsCancellationRequested)
                        tokenSource.Cancel();

                    isTokenValid = false;
                };

                int allDirectoryCount = 0;

                // Enabling privileges to the current token. This will fail if the current token doesn't have these privileges.
                using (PrivilegeCookie privilegeCookie = AccessControl.Ensure(new string[] { "SeBackupPrivilege", "SeRestorePrivilege" })) {

                    // Listing directories and files recursively.
                    // We do this separately so we can have the total count to add to our progress monitor.
                    ConcurrentQueue<Exception> exceptions = new ConcurrentQueue<Exception>();
                    ConcurrentBag<List<IO.DirectoryFileInformation>> fsObjectInfoListBag = new ConcurrentBag<List<IO.DirectoryFileInformation>>();
                    Parallel.ForEach(pathList, new ParallelOptions { CancellationToken = tokenSource.Token }, path => {
                        try {
                            List<IO.DirectoryFileInformation> currentList = new List<IO.DirectoryFileInformation>();
                            IO.GetDirectoryFileInfoRecurse(path, ref currentList, tokenSource.Token);

                            allDirectoryCount += currentList.Count;
                            progressMonitor["FileCount"] += currentList.Select(info => info.Files.Count).Sum() + allDirectoryCount;
                            fsObjectInfoListBag.Add(currentList);
                        }
                        catch (Exception ex) {
                            exceptions.Enqueue(ex);
                        }
                    });

                    // If something failed we ball.
                    if (!exceptions.IsEmpty) {
                        isTokenValid = false;
                        throw new AggregateException(exceptions);
                    }

                    // Creating the tasks to delete the files.
                    List<Task> taskList = new List<Task>(allDirectoryCount);
                    ConcurrentBag<string> remainingDirectoryBag = new ConcurrentBag<string>();
                    foreach (List<IO.DirectoryFileInformation> fsInfoList in fsObjectInfoListBag) {
                        tokenSource.Token.ThrowIfCancellationRequested();

                        foreach (IO.DirectoryFileInformation fsInfo in fsInfoList) {
                            tokenSource.Token.ThrowIfCancellationRequested();

                            taskList.Add(Task.Run(() => {
                                switch (fsInfo.Type) {
                                    case IO.FsObjectType.Directory:

                                        // If we have a lot of files we process them in parallel.
                                        if (fsInfo.Files.Count < 500000) {
                                            for (int j = 0; j < fsInfo.Files.Count; j++) {
                                                tokenSource.Token.ThrowIfCancellationRequested();
                                                try {
                                                    List<int> closedHandleList = new List<int>();
                                                    IO.DeleteFileClosingOpenHandles(fsInfo.Files[j], tokenSource.Token, ref closedHandleList);
                                                    foreach (int processId in closedHandleList) {
                                                        closedHandlesMonitor.Add(new Tuple<string, int>(fsInfo.Files[j], processId));
                                                    }
                                                }
                                                catch (Exception ex) {
                                                    errorList.Add(new DeleteFileErrorInfo(fsInfo.Files[j], ex));
                                                }
                                                progressMonitor["Progress"]++;
                                            }
                                        }
                                        else {
                                            Parallel.ForEach(fsInfo.Files, new ParallelOptions() { CancellationToken = tokenSource.Token }, filePath => {
                                                tokenSource.Token.ThrowIfCancellationRequested();
                                                try {
                                                    List<int> closedHandleList = new List<int>();
                                                    IO.DeleteFileClosingOpenHandles(filePath, tokenSource.Token, ref closedHandleList);
                                                    foreach (int processId in closedHandleList) {
                                                        closedHandlesMonitor.Add(new Tuple<string, int>(filePath, processId));
                                                    }
                                                }
                                                catch (Exception ex) {
                                                    errorList.Add(new DeleteFileErrorInfo(filePath, ex));
                                                }
                                                progressMonitor["Progress"]++;
                                            });
                                        }

                                        // At this point there are no more files in the folder (if nothing failed).
                                        // So if the folder doesn't have sub-directories we delete it.
                                        if (!fsInfo.HasSubDirectory) {
                                            try {
                                                List<int> closedHandleList = new List<int>();
                                                IO.DeleteDirectoryClosingOpenHandles(fsInfo.FullName, tokenSource.Token, ref closedHandleList);
                                                foreach (int processId in closedHandleList) {
                                                    closedHandlesMonitor.Add(new Tuple<string, int>(fsInfo.FullName, processId));
                                                }
                                            }
                                            catch (Exception ex) {
                                                errorList.Add(new DeleteFileErrorInfo(fsInfo.FullName, ex));
                                            }
                                            progressMonitor["Progress"]++;
                                        }
                                        else
                                            remainingDirectoryBag.Add(fsInfo.FullName);

                                        break;

                                    case IO.FsObjectType.File:
                                        try {
                                            // If it's a file we just delete it.
                                            List<int> closedHandleList = new List<int>();
                                            IO.DeleteFileClosingOpenHandles(fsInfo.FullName, tokenSource.Token, ref closedHandleList);
                                            foreach (int processId in closedHandleList) {
                                                closedHandlesMonitor.Add(new Tuple<string, int>(fsInfo.FullName, processId));
                                            }
                                        }
                                        catch (Exception ex) {
                                            errorList.Add(new DeleteFileErrorInfo(fsInfo.FullName, ex));
                                        }
                                        progressMonitor["Progress"]++;

                                        break;
                                }
                            }, tokenSource.Token));
                        }
                    }

                    // Waiting the tasks to complete.
                    Task.WaitAll(taskList.ToArray(), tokenSource.Token);

                    // Deleting remaining directories.
                    // We order by name descending so we delete sub-directories first.
                    foreach (string directory in remainingDirectoryBag.OrderByDescending(path => path.Length)) {
                        tokenSource.Token.ThrowIfCancellationRequested();
                        try {
                            List<int> closedHandleList = new List<int>();
                            IO.DeleteDirectoryClosingOpenHandles(directory, tokenSource.Token, ref closedHandleList);
                            foreach (int processId in closedHandleList) {
                                closedHandlesMonitor.Add(new Tuple<string, int>(directory, processId));
                            }
                        }
                        catch (Exception ex) {
                            errorList.Add(new DeleteFileErrorInfo(directory, ex));
                        }
                        progressMonitor["Progress"]++;
                    }
                }
            }

            isTokenValid = false;

            return errorList.ToArray();
        }
    }

    // File utilities.
    internal static class IO
    {
        internal enum FsObjectType
        {
            Directory,
            File,
        }

        internal sealed class DirectoryFileInformation
        {
            internal FsObjectType Type { get; set; }
            internal string FullName { get; set; }
            internal bool HasSubDirectory { get; set; }
            internal List<string> Files { get; set; }

            internal DirectoryFileInformation(FsObjectType type, string path)
            {
                this.Type = type;
                this.FullName = path;
                this.HasSubDirectory = false;
                this.Files = new List<string>();
            }
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
        private static extern SafeFileHandle CreateFile(
            string lpFileName,
            int dwDesiredAccess,
            int dwShareMode,
            IntPtr lpSecurityAttributes,
            int dwCreationDisposition,
            int dwFlagsAndAttributes,
            IntPtr hTemplateFile
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryDirectoryFile(
            SafeFileHandle FileHandle,
            IntPtr Event,
            IntPtr ApcRoutine, // IO_APC_ROUTINE*
            IntPtr ApcContext,
            ref IO_STATUS_BLOCK IoStatusBlock,
            IntPtr FileInformation,
            int Length,
            int FileInformationClass,
            bool ReturnSingleEntry,
            IntPtr FileName, // UNICODE_STRING*
            bool RestartScan
        );

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryDosDeviceW")]
        private static extern int QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "DeleteFileW")]
        [return:  MarshalAs(UnmanagedType.Bool)]
        private static extern bool DeleteFile(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "RemoveDirectoryW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool RemoveDirectory(string lpPathName);

        // Deletes an empty directory.
        internal static void DeleteDirectoryClosingOpenHandles(string path, CancellationToken token, ref List<int> closedHandleProcessIds)
        {
            token.ThrowIfCancellationRequested();

            // Checking if it's a big path.
            // Check parameter 'lpPathName' from 'RemoveDirectoryW'.
            string finalPath;
            if (path.Length > 260)
                finalPath = @"\\?\" + path;
            else
                finalPath = path;

            if (!RemoveDirectory(finalPath)) {
                token.ThrowIfCancellationRequested();
                int lastError = Marshal.GetLastWin32Error();

                // 32 = file is open in another process.
                if (lastError == 32) {

                    // Opening the file ourselves.
                    // 128 = FILE_READ_ATTRIBUTES;
                    // 7 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                    // 3 = OPEN_EXISTING
                    // 33554432 = FILE_FLAG_BACKUP_SEMANTICS
                    using (SafeFileHandle hFile = CreateFile(finalPath, 128, 7, IntPtr.Zero, 3, 33554432, IntPtr.Zero)) {
                        if (hFile.IsInvalid || hFile.IsClosed)
                            throw new NativeException(Marshal.GetLastWin32Error());

                        // Attempting to close open handles.
                        try { NtUtilities.CloseExternalHandlesToFile(hFile, GetFileDevicePathFromDosPath(path), token, ref closedHandleProcessIds); }
                        catch { }

                        token.ThrowIfCancellationRequested();

                        // At this point if it fails ain't nothing we can do.
                        if (!DeleteFile(finalPath))
                            throw new NativeException(Marshal.GetLastWin32Error());
                    }
                }
                else
                    throw new NativeException(lastError);
            }
        }

        // Deletes a file. If a file has one or more open handles it tries to close them.
        internal static void DeleteFileClosingOpenHandles(string path, CancellationToken token, ref List<int> closedHandleProcessIds)
        {
            token.ThrowIfCancellationRequested();

            // Checking if it's a big path.
            // Check parameter 'lpFileName' from 'CreateFileW' and 'DeleteFileW'.
            string finalPath;
            if (path.Length > 260)
                finalPath = @"\\?\" + path;
            else
                finalPath = path;

            if (!DeleteFile(finalPath)) {
                token.ThrowIfCancellationRequested();
                int lastError = Marshal.GetLastWin32Error();

                // 32 = file is open in another process.
                if (lastError == 32) {

                    // Opening the file ourselves.
                    // 128 = FILE_READ_ATTRIBUTES;
                    // 7 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
                    // 3 = OPEN_EXISTING
                    // 33554432 = FILE_FLAG_BACKUP_SEMANTICS
                    using (SafeFileHandle hFile = CreateFile(finalPath, 128, 7, IntPtr.Zero, 3, 33554432, IntPtr.Zero)) {
                        if (hFile.IsInvalid || hFile.IsClosed)
                            throw new NativeException(Marshal.GetLastWin32Error());

                        // Attempting to close open handles.
                        try { NtUtilities.CloseExternalHandlesToFile(hFile, GetFileDevicePathFromDosPath(path), token, ref closedHandleProcessIds); }
                        catch { }

                        token.ThrowIfCancellationRequested();

                        // At this point if it fails ain't nothing we can do.
                        if (!DeleteFile(finalPath))
                            throw new NativeException(Marshal.GetLastWin32Error());
                    }
                }
                else
                    throw new NativeException(lastError);
            }
        }

        // Lists files and folders recursively for a directory.
        internal static unsafe void GetDirectoryFileInfoRecurse(string rootPath, ref List<DirectoryFileInformation> infoList, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();

            // Checking if it's a big path.
            // Check parameter 'lpFileName' from 'CreateFileW''.
            string openHandlePath;
            if (rootPath.Length > 260)
                openHandlePath = @"\\?\" + rootPath;
            else
                openHandlePath = rootPath;

            // When adding support to provider-aware parameters we need to consider files.
            // If it's a file we just add an entry to be consumed by the caller.
            if (File.Exists(openHandlePath)) {
                infoList.Add(new DirectoryFileInformation(FsObjectType.File, rootPath));
                return;
            }
            else {
                if (!Directory.Exists(openHandlePath))
                    throw new FileNotFoundException("Could not find '" + rootPath + "' because it doesn't exist.");
            }

            // Getting a handle to the file (opening it).
            // 1 = FILE_LIST_DIRECTORY
            // 7 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
            // 3 = OPEN_EXISTING
            // 33554432 = FILE_FLAG_BACKUP_SEMANTICS
            using (SafeFileHandle hFile = CreateFile(openHandlePath, 1, 7, IntPtr.Zero, 3, 33554432, IntPtr.Zero)) {
                if (hFile.IsInvalid || hFile.IsClosed)
                    throw new NativeException(Marshal.GetLastWin32Error());

                int bufferSize = 8192;
                using (ScopedBuffer buffer = new ScopedBuffer(bufferSize)) {

                    // Getting the initial buffer;
                    // 2 = FILE_INFORMATION_CLASS.FileFullDirectoryInformation
                    IO_STATUS_BLOCK statusBlock = default(IO_STATUS_BLOCK);
                    int status = NtQueryDirectoryFile(hFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref statusBlock, buffer, bufferSize, 2, false, IntPtr.Zero, false);
                    if (status != 0)
                        throw new NativeException(status, true);

                    // Ending with a terminator char.
                    string rootNormalizedName;
                    if (rootPath.EndsWith("\\"))
                        rootNormalizedName = rootPath;
                    else
                        rootNormalizedName = rootPath + "\\";

                    IntPtr offset = buffer;
                    FILE_FULL_DIR_INFORMATION* currentInfo;
                    DirectoryFileInformation entry = new DirectoryFileInformation(FsObjectType.Directory, rootNormalizedName);
                    do {
                        token.ThrowIfCancellationRequested();

                        do {
                            // Going through each entry in our buffer.
                            token.ThrowIfCancellationRequested();

                            currentInfo = (FILE_FULL_DIR_INFORMATION*)offset;
                            string name = currentInfo->FileName;

                            // Skipping system paths.
                            if (name.Equals(".", StringComparison.Ordinal) || name.Equals("..", StringComparison.Ordinal)) {
                                offset = IntPtr.Add(offset, currentInfo->NextEntryOffset);
                                continue;
                            }

                            // Checking if it's a directory.
                            if ((currentInfo->FileAttributes & 0x00000010) == 0x00000010) {

                                // Calling recursively.
                                GetDirectoryFileInfoRecurse(rootNormalizedName + name, ref infoList, token);
                                entry.HasSubDirectory = true;
                            }
                            else
                                entry.Files.Add(rootNormalizedName + name);

                            offset = IntPtr.Add(offset, currentInfo->NextEntryOffset);

                        } while (currentInfo->NextEntryOffset != 0);

                        // Refreshing the buffer until there's no more items.
                        // 2 = FILE_INFORMATION_CLASS.FileFullDirectoryInformation
                        status = NtQueryDirectoryFile(hFile, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref statusBlock, buffer, bufferSize, 2, false, IntPtr.Zero, false);
                        if (status != 0 && status != -2147483642)
                            throw new NativeException(status, true);

                        offset = buffer;

                    } while (status == 0 && buffer != IntPtr.Zero);

                    infoList.Add(entry);
                }
            }
        }

        // Converts a 'DOS' path to a device path.
        // E.g., C:\SomeFolder ~> \Device\HardDrive3\SomeFolder
        private static string GetFileDevicePathFromDosPath(string path)
        {
            string drive = string.Format("{0}:", path[0]);
            StringBuilder buffer = new StringBuilder(260);
            if (QueryDosDevice(drive, buffer, 260) == 0)
                throw new NativeException(Marshal.GetLastWin32Error());

            return string.Format("{0}\\{1}", buffer.ToString(), path.Remove(0, 3));
        }
    }

    // Process utilities.
    internal static class ProcessAndThread
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern SafeNativeHandle OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetCurrentProcess();

        // Opens a handle to a process.
        internal static SafeNativeHandle SafeOpenProcess(int desiredAccess, bool inheritHandle, int processId)
        {
            SafeNativeHandle hProcess = OpenProcess(desiredAccess, inheritHandle, processId);
            if (hProcess.IsInvalid || hProcess.IsClosed)
                throw new NativeException(Marshal.GetLastWin32Error());

            return hProcess;
        }
    }

    // NT APIs.
    internal static class NtUtilities
    {
        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryObject(IntPtr Handle, int ObjectInformationClass, IntPtr ObjectInformation, int ObjectInformationLength, out int ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtDuplicateObject(IntPtr SourceProcessHandle, IntPtr SourceHandle, IntPtr TargetProcessHandle, out IntPtr TargetHandle, int DesiredAccess, int HandleAttributes, int Options);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationProcess(IntPtr ProcessHandle, int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [DllImport("ntdll.dll", SetLastError = true)]
        private static extern int NtQueryInformationFile(IntPtr FileHande, ref IO_STATUS_BLOCK IoStatusBlock, IntPtr FileInformation, int Length, int FileInformationClass);

        // Attempts to close external handles to a file, searching for the owning processes first.
        internal static unsafe void CloseExternalHandlesToFile(SafeFileHandle hFile, string devicePath, CancellationToken token, ref List<int> closedHandleProcessIds)
        {
            token.ThrowIfCancellationRequested();

            // Getting the processes that have open handles to this file.
            int bufferSize = 1 << 10;
            List<int> processIdList = new List<int>();
            IO_STATUS_BLOCK statusBlock = new IO_STATUS_BLOCK();
            using (ScopedBuffer buffer = new ScopedBuffer(bufferSize)) {
                int status = 0;

                // Since the handle list might change we call this in a loop until we have the right size buffer.
                // This is somewhat common on NT APIs.
                do {
                    token.ThrowIfCancellationRequested();

                    // 47 = FILE_INFORMATION_CLASS.FileProcessIdsUsingFileInformation
                    status = NtQueryInformationFile(hFile.DangerousGetHandle(), ref statusBlock, buffer, bufferSize, 47);
                    if (status == 0)
                        break;

                    // -1073741820 = buffer too small
                    if (status != -1073741820)
                        throw new NativeException(status, true);

                    bufferSize = (int)statusBlock.Information;
                    buffer.Resize(bufferSize);

                } while (status == -1073741820);

                // Caching the process ID list.
                FILE_PROCESS_IDS_USING_FILE_INFORMATION* pidUsingFileInfo = (FILE_PROCESS_IDS_USING_FILE_INFORMATION*)(IntPtr)buffer;
                processIdList.AddRange(pidUsingFileInfo->ProcessIdList);
            }

            // Calling the method to actually close the handles.
            CloseExternalHandlesToFile(processIdList, devicePath, token, ref closedHandleProcessIds);
        }

        // Attempts to close external handles to a file from a process ID list.
        // It does that by opening a handle to a process, enumerating its handles, duplicating them, querying information to see
        // if it's a handle to our file, if it is we duplicate again with 'DUPLICATE_CLOSE_SOURCE' to close the original handle
        private static unsafe void CloseExternalHandlesToFile(List<int> processIdList, string devicePath, CancellationToken token, ref List<int> closedHandleProcessIds)
        {
            for (int i = 0; i < processIdList.Count; i++) {
                token.ThrowIfCancellationRequested();

                // Opening a handle to the process;
                // 1104 = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE
                SafeNativeHandle hProcess;
                try { hProcess = ProcessAndThread.SafeOpenProcess(1104, false, processIdList[i]); }
                catch { continue; }

                using (hProcess) {
                    int status = 0;
                    int bufferSize = 9216;
                    using (ScopedBuffer buffer = new ScopedBuffer(bufferSize)) {
                        do {
                            // Getting a list of all the processes handles.
                            token.ThrowIfCancellationRequested();

                            // 51 = PROCESSINFOCLASS.ProcessHandleInformation
                            status = NtQueryInformationProcess(hProcess.DangerousGetHandle(), 51, buffer, bufferSize, out bufferSize);
                            if (status == 0)
                                break;

                            // -1073741820 = buffer too small
                            if (status != -1073741820)
                                throw new NativeException(status, true);

                            bufferSize += 1024;
                            buffer.Resize(bufferSize);

                        } while (status == -1073741820);

                        // Going through each process handle.
                        IntPtr hCurrentProcess = ProcessAndThread.GetCurrentProcess();
                        PROCESS_HANDLE_SNAPSHOT_INFORMATION* processHandleInfo = (PROCESS_HANDLE_SNAPSHOT_INFORMATION*)(IntPtr)buffer;
                        foreach (PROCESS_HANDLE_TABLE_ENTRY_INFO handleInfo in processHandleInfo->Handles) {
                            token.ThrowIfCancellationRequested();

                            // Duplicating the handle.
                            // 2 = DUPLICATE_SAME_ACCESS
                            IntPtr hDup;
                            status = NtDuplicateObject(hProcess.DangerousGetHandle(), handleInfo.HandleValue, hCurrentProcess, out hDup, 0, 0, 2);
                            if (status != 0)
                                continue;

                            // Querying the object type.
                            // 2 = OBJECT_INFORMATION_CLASS.ObjectTypeInformation
                            int typeBufferSize = 1024;
                            using (ScopedBuffer typeBuffer = new ScopedBuffer(typeBufferSize)) {
                                status = NtQueryObject(hDup, 2, typeBuffer, typeBufferSize, out typeBufferSize);
                                if (status != 0) {
                                    Common.CloseHandle(hDup);
                                    throw new NativeException(status, true);
                                }

                                // If it's a file we go further.
                                var typeName = ((OBJECT_TYPE_INFORMATION*)(IntPtr)typeBuffer)->TypeName.String.Trim('\0');
                                if (typeName.Equals("File", StringComparison.OrdinalIgnoreCase)) {

                                    // Querying the object name. We do this in a task because some asyncrhonous objects, like pipes
                                    // block the call to 'NtQueryObject' forever.
                                    Task<string> getNameTask = Task.Run(() => {
                                        int nameBufferSize = 1024;
                                        string output = string.Empty;
                                        using (ScopedBuffer nameBuffer =  new ScopedBuffer(nameBufferSize)) {

                                            // 1 = OBJECT_INFORMATION_CLASS.ObjectNameInformation
                                            int getNameStatus = NtQueryObject(hDup, 1, nameBuffer, nameBufferSize, out nameBufferSize);
                                            if (status != 0)
                                                throw new NativeException(status, true);

                                            output = ((OBJECT_NAME_INFORMATION*)(IntPtr)nameBuffer)->Name.String;
                                        }

                                        return output;
                                    }, token);

                                    try {
                                        // Checking if it's our file.
                                        if (getNameTask.Wait(100, token)) {
                                            if (!string.IsNullOrEmpty(getNameTask.Result) && getNameTask.Result.Equals(devicePath, StringComparison.OrdinalIgnoreCase)) {
                                                Common.CloseHandle(hDup);

                                                // Duplicating the handle again to close the source.
                                                // 1 = DUPLICATE_CLOSE_SOURCE
                                                status = NtDuplicateObject(hProcess.DangerousGetHandle(), handleInfo.HandleValue, hCurrentProcess, out hDup, 0, 0, 1);
                                                if (status != 0)
                                                    throw new NativeException(status, true);

                                                closedHandleProcessIds.Add(processIdList[i]);
                                            }
                                        }

                                        // Closing our handle.
                                        Common.CloseHandle(hDup);
                                    }
                                    catch {
                                        Common.CloseHandle(hDup);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Security utilities.
    internal static class AccessControl
    {
        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, int DesiredAccess, out SafeAccessTokenHandle pHandle);

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeValueW")]
        private static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "LookupPrivilegeNameW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool LookupPrivilegeName(IntPtr lpSystemName, ref LUID lpLuid, StringBuilder lpName, ref uint cchName);

        [DllImport("Advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool AdjustTokenPrivileges(SafeAccessTokenHandle TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

        [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "GetTokenInformation", ExactSpelling = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTokenInformation(SafeAccessTokenHandle TokenHandle, int TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        // Ensures that a list of privileges are enabled in the current token.
        internal static PrivilegeCookie Ensure(string[] privilegeNames)
        {
            // Opening a handle to the current process token.
            // 40 = TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES
            SafeAccessTokenHandle hToken;
            List<LUID_AND_ATTRIBUTES> enabledLatList = new List<LUID_AND_ATTRIBUTES>();
            if (!OpenProcessToken(ProcessAndThread.GetCurrentProcess(), 40, out hToken))
                throw new NativeException(Marshal.GetLastWin32Error());

            // Getting the privilege list for this token.
            Dictionary<string, LUID_AND_ATTRIBUTES> tokenPrivileges = GetTokenPrivileges(hToken);
            foreach (string privilegeName in privilegeNames) {
                LUID_AND_ATTRIBUTES lat;
                if (tokenPrivileges.TryGetValue(privilegeName, out lat)) {

                    // Attempting to enable the privilege, if not enabled already.
                    // 1 = SE_PRIVILEGE_ENABLED_BY_DEFAULT
                    // 2 = SE_PRIVILEGE_ENABLED
                    if ((lat.Attributes & 2) != 2 && (lat.Attributes & 1) != 1) {
                        AdjustTokenPrivileges(hToken, lat, 2);
                        enabledLatList.Add(lat);
                    }
                }
                else
                    // A privilege is not held by the client.
                    throw new NativeException(1314);
            }

            return new PrivilegeCookie(enabledLatList.ToArray(), hToken);
        }

        // A wrapper for 'AdjustTokenPrivileges'.
        internal static void AdjustTokenPrivileges(SafeAccessTokenHandle hToken, LUID_AND_ATTRIBUTES luidAndAttributes, uint privilegeAttribute)
        {
            TOKEN_PRIVILEGES privileges = new TOKEN_PRIVILEGES() { Privileges = new LUID_AND_ATTRIBUTES[1] { luidAndAttributes } };

            privileges.PrivilegeCount = 1;
            privileges.Privileges[0].Attributes = privilegeAttribute;

            if (!AdjustTokenPrivileges(hToken, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
                throw new NativeException(Marshal.GetLastWin32Error());
        }

        // Lists the privileges to a given token handle.
        private static unsafe Dictionary<string, LUID_AND_ATTRIBUTES> GetTokenPrivileges(SafeAccessTokenHandle hToken)
        {
            // Getting buffer size.
            // 3 = TOKEN_INFORMATION_CLASS.TokenPrivileges
            int bytesNeeded;
            GetTokenInformation(hToken, 3, IntPtr.Zero, 0, out bytesNeeded);

            Dictionary<string, LUID_AND_ATTRIBUTES> output = new Dictionary<string, LUID_AND_ATTRIBUTES>();
            using (ScopedBuffer buffer = new ScopedBuffer(bytesNeeded)) {

                // Getting privilege information.
                // 3 = TOKEN_INFORMATION_CLASS.TokenPrivileges
                if (!GetTokenInformation(hToken, 3, buffer, bytesNeeded, out bytesNeeded))
                    throw new NativeException(Marshal.GetLastWin32Error());

                uint privilegeCount = *(uint*)(IntPtr)buffer;
                LUID_AND_ATTRIBUTES* privOffset = (LUID_AND_ATTRIBUTES*)((byte*)(IntPtr)buffer + sizeof(uint));
                for (uint i = 0; i < privilegeCount; i++) {
                    LUID_AND_ATTRIBUTES currentPrivilege = new LUID_AND_ATTRIBUTES() {
                        Attributes = privOffset->Attributes,
                        Luid = new LUID() {
                            LowPart = privOffset->Luid.LowPart,
                            HighPart = privOffset->Luid.HighPart,
                        }
                    };

                    // Getting the privilege name string.
                    uint buffCharSize = 260;
                    StringBuilder nameBuffer = new StringBuilder(260);
                    if (!LookupPrivilegeName(IntPtr.Zero, ref currentPrivilege.Luid, nameBuffer, ref buffCharSize))
                        throw new NativeException(Marshal.GetLastWin32Error());

                    output.Add(nameBuffer.ToString(), currentPrivilege);

                    privOffset++;
                }
            }

            return output;
        }
    }

    // Common utilities.
    internal static class Common
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr hObject);
    }

    // Represents one or more privileges added to the current token.
    internal sealed class PrivilegeCookie : IDisposable
    {
        private readonly LUID_AND_ATTRIBUTES[] _enabledPrivileges;
        private readonly SafeAccessTokenHandle _accessTokenHandle;

        internal PrivilegeCookie(LUID_AND_ATTRIBUTES[] enabledPrivileges, SafeAccessTokenHandle accessTokenHandle)
        {
            _enabledPrivileges = enabledPrivileges;
            _accessTokenHandle = accessTokenHandle;
        }

        public void Dispose()
        {
            foreach (LUID_AND_ATTRIBUTES lat in _enabledPrivileges)
                // 0 = SE_PRIVILEGE_NONE
                // If we use 'SE_PRIVILEGE_REMOVED (4)' we remove the privilege from the token.
                // This is irreversible.
                AccessControl.AdjustTokenPrivileges(_accessTokenHandle, lat, 0);

            _accessTokenHandle.Dispose();
            GC.SuppressFinalize(this);
        }
    }

    // Wraps an unmanaged heap allocated memory buffer.
    internal sealed class ScopedBuffer : IDisposable
    {
        private IntPtr _buffer;
        private bool _isDisposed;

        internal ScopedBuffer(int size)
        {
            _buffer = Marshal.AllocHGlobal(size);
            _isDisposed = false;
        }

        internal void Resize(int newSize)
        {
            if (_isDisposed)
                throw new ObjectDisposedException("ScopedBuffer");

            Marshal.FreeHGlobal(_buffer);
            _buffer = Marshal.AllocHGlobal(newSize);
        }

        public void Dispose()
        {
            if (!_isDisposed) {
                Marshal.FreeHGlobal(_buffer);
                _isDisposed = true;
            }

            GC.SuppressFinalize(this);
        }

        public static implicit operator IntPtr(ScopedBuffer managedBuffer)
        {
            if (managedBuffer._isDisposed)
                throw new ObjectDisposedException("ScopedBuffer");

            return managedBuffer._buffer;
        }
    }

    // Wraps an operating system native handle.
    internal sealed class SafeNativeHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeNativeHandle()
            : base(ownsHandle: true) { }

        internal SafeNativeHandle(IntPtr existingHandle)
            : base(ownsHandle: true)
        {
            SetHandle(existingHandle);
        }

        internal SafeNativeHandle(IntPtr existingHandle, bool ownsHandle)
            : base(ownsHandle)
        {
            SetHandle(existingHandle);
        }

        protected override bool ReleaseHandle()
        {
            return Common.CloseHandle(handle);
        }
    }

    // Exceptions thrown by unmanaged code or NT APIs.
    public sealed class NativeException : SystemException
    {
        public int ErrorCode { get; internal set; }

        public NativeException(int errorCode, bool isNt = false)
            : base(GetMessageFromNativeError(errorCode, isNt))
        {
            this.ErrorCode = errorCode;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "FormatMessageW")]
        private static extern int FormatMessage(int dwFlags, IntPtr lpSource, int dwMessageId, int dwLanguage, out IntPtr lpBuffer, int nSize, IntPtr Arguments);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetModuleHandleW")]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        // Gets the message from an error code or NTSTATUS.
        private static string GetMessageFromNativeError(int errorCode, bool isNt = false)
        {
            IntPtr buffer;
            string output = string.Empty;
            if (isNt) {
                // 2816 = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS
                IntPtr hNtdll = GetModuleHandle("ntdll.dll");
                int res = FormatMessage(2816, hNtdll, errorCode, 0, out buffer, 0, IntPtr.Zero);
                if (res > 0) {
                    output = Marshal.PtrToStringUni(buffer);
                    LocalFree(buffer);
                }
            }
            else {
                // 4864 = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS
                int res = FormatMessage(4864, IntPtr.Zero, errorCode, 0, out buffer, 0, IntPtr.Zero); ;
                if (res > 0) {
                    output = Marshal.PtrToStringUni(buffer);
                    LocalFree(buffer);
                }
            }

            return output;
        }
    }
}
'@

    $resolvedPathList = [System.Collections.Generic.List[string]]::new()
}
Process {
    # Simple provider awareness implementation.
    if ($PSCmdlet.ParameterSetName -eq 'byPath') {
        $pathList = $Path
        $shouldExpandWildcards = $true
    }
    else {
        $pathList = $LiteralPath
        $shouldExpandWildcards = $false
    }

    # Resolving paths and possibly globbed paths.
    foreach ($singlePath in $pathList) {
        $driveInfo = $null
        $providerInfo = $null
        if ($shouldExpandWildcards) {
            $resolvedPathList.AddRange($PSCmdlet.GetResolvedProviderPathFromPSPath($singlePath, [ref]$providerInfo))
        }
        else {
            $resolvedPathList.Add($PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($singlePath, [ref]$providerInfo, [ref]$driveInfo))
        }

        if ($providerInfo.Name -ne 'FileSystem') {
            throw [ArgumentException]::new("This function can't be used with the '$($providerInfo.Name)' provider.")
        }
    }
}
End {
    # If we couldn't resolve to any path we ball.
    if ($resolvedPathList.Count -lt 1) {
        throw [ArgumentException]::new("The input didn't resolved to any path.")
    }

    # Creating the monitoring objects for the progress and closed handles.
    $closedHandleMonitor = [System.Collections.Concurrent.ConcurrentBag[Tuple[string, int]]]::new()
    $messenger = [System.Collections.Concurrent.ConcurrentDictionary[string, int]]::new()
    [void]$messenger.TryAdd('FileCount', 0)
    [void]$messenger.TryAdd('Progress', 0)

    # Creating the main task.
    $ps = [powershell]::Create()
    try {
        [void]$ps.AddScript({

            param($ApiSignature, $ResolvedPaths, $Messenger, $ClosedHandleMonitor)

            # 'Add-Type' acts differently between Windows PowerShell and PowerShell.
            if ($PSVersionTable.PSEdition -eq 'Core') {
                $addTypeSplat = @{
                    TypeDefinition       = $ApiSignature
                    CompilerOptions      = '/unsafe'
                    ReferencedAssemblies = @(
                        'System.Linq.dll'
                        'System.Console.dll'
                        'System.Collections.dll'
                        'System.Collections.Concurrent.dll'
                        'System.Threading.Tasks.Parallel.dll'
                        'System.Security.Principal.Windows.dll'
                    )
                }
                Add-Type @addTypeSplat -ErrorAction Stop
            }
            else {
                $compilerParams = [System.CodeDom.Compiler.CompilerParameters]::new()
                $compilerParams.CompilerOptions = '/unsafe'
                [void]$compilerParams.ReferencedAssemblies.Add('System.dll')
                [void]$compilerParams.ReferencedAssemblies.Add('System.Core.dll')
                Add-Type -TypeDefinition $ApiSignature -CompilerParameters $compilerParams -ErrorAction Stop
            }

            # Calling the main API.
            return [Utilities.Obliterator]::Obliterate($ResolvedPaths, $Messenger, $ClosedHandleMonitor)
        }).AddParameter('ApiSignature', $theThing).AddParameter('ResolvedPaths', $resolvedPathList.ToArray()).AddParameter('Messenger', $messenger).AddParameter('ClosedHandleMonitor', $closedHandleMonitor)

        # Starting the task and entering the monitoring loop.
        $handle = $ps.BeginInvoke()
        $spinWait = [System.Threading.SpinWait]::new()
        $advertisedClosedHandles = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[int]]]::new()
        do {
            # Writing progress.
            if ($messenger.FileCount -gt 0) {
                Write-Progress -Activity 'Deleting files' -Status "Progress: $($messenger.Progress)/$($messenger.FileCount)" -PercentComplete (($messenger.Progress / $messenger.FileCount) * 100)
            }

            # Checking if any handles were closed for any of the objects.
            foreach ($closedHandle in $closedHandleMonitor) {
                $possibleFile = $null
                if ($advertisedClosedHandles.TryGetValue($closedHandle.Item1, [ref]$possibleFile)) {

                    # Handles from multiple processes might have been closed for one object.
                    # We alert them all.
                    if (!$possibleFile.Contains($closedHandle.Item2)) {
                        Write-Warning "A handle to a file system object was closed. Process ID: $($closedHandle.Item2). Path: $($closedHandle.Item1)."
                        [void]$advertisedClosedHandles[$closedHandle.Item1].Add($closedHandle.Item2)
                    }
                }
                else {
                    Write-Warning "A handle to a file system object was closed. Process ID: $($closedHandle.Item2). Path: $($closedHandle.Item1)."
                    [void]$advertisedClosedHandles.Add($closedHandle.Item1, [System.Collections.Generic.List[int]]::new())
                    [void]$advertisedClosedHandles[$closedHandle.Item1].Add($closedHandle.Item2)
                }
            }

            $spinWait.SpinOnce()

        } while ($ps.InvocationStateInfo.State -eq 'Running')
        Write-Progress -Activity 'Deleting files' -Status "Progress: $($messenger.Progress)/$($messenger.FileCount)" -Completed

        # Marshaling any errors that might have happened.
        if ($ps.HadErrors -or $ps.Streams.Error.Count -gt 1) {
            if ($ps.Streams.Error.Count -gt 0) {
                foreach ($record in $ps.Streams.Error) {
                    $exType = $record.Exception.InnerException.GetType()

                    # We skip cancellation exceptions.
                    if ($exType -ne [type][OperationCanceledException]) {

                        # Aggregate exceptions are thrown when more than one asynchronous task throws an exception.
                        # We output them all to the stream.
                        if ($exType -eq [type][AggregateException]) {
                            foreach ($innerException in $record.Exception.InnerException.InnerExceptions) {
                                Write-Error -Exception $innerException
                                $lastErrorRecord = $innerException
                            }
                        }
                        else {
                            Write-Error -ErrorRecord $record
                            $lastErrorRecord = $record
                        }
                    }
                }
            }
            else {
                # At this point the error stream was empty, so we check the 'Reason'.
                if ($null -ne $ps.InvocationStateInfo.Reason -and $ps.InvocationStateInfo.Reason.GetType() -ne [type][OperationCanceledException]) {
                    throw $ps.InvocationStateInfo.Reason
                }
                else {
                    # Here we know there was an error, but we couldn't find information about it.
                    if ($null -eq $lastErrorRecord) {
                        throw 'The PowerShell task had errors, but no exception was found.'
                    }
                }
            }
        }
        else {
            # Collecting the results and writing them to the stream.
            $result = $ps.EndInvoke($handle)
            foreach ($item in $result) {
                Write-Output -InputObject $item
            }
        }
    }
    finally {
        # Disposing of the task.
        $ps.Dispose()
    }
}