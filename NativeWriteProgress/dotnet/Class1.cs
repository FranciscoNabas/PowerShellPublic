using System.Runtime.InteropServices;
using System.Management.Automation;
using CCLRTest;
using Microsoft.Win32.SafeHandles;

namespace dotnet
{
    // New-ClrWriteProgress Cmdlet.
    [Cmdlet(VerbsCommon.New, "ClrWriteProgress")]
    public class NewClrWriteProgressCommand : PSCmdlet
    {
        // Getting the memory mapped wrapper.
        private readonly ProgressDataSharedMemory _sharedProgressData = ProgressDataSharedMemory.GetMappedMemory();

        protected override void ProcessRecord()
        {
            Wrapper unw = new();
            Wrapper.WrappedWriteProgress wpfunc = new(WriteProgressAction);

            for(uint i = 0; i < 100; i++)
            {
                // Calling unmanaged WriteProgress each 100ms.
                Thread.Sleep(100);
                unw.WriteProgress(wpfunc, _sharedProgressData.DangerousGetMappedFileHandle(), "Testing progress", "Counting...", i);
            }
        }

        // Cleanup.
        // This will dispose of any active views, and the memory mapped file as well.
        protected override void EndProcessing()
            => _sharedProgressData?.Dispose();

        // The callback called by unmanaged code.
        private void WriteProgressAction(ulong dataSize)
        {
            MAPPED_PROGRESS_DATA? progressData;

            // Getting a view of the mapped memory.
            SafeMemoryMappedViewHandle mappedView = _sharedProgressData.MapView(out Guid viewId, 4, 0, (uint)dataSize);

            // Marshaling it.
            // Here we could have used a wrapped object, but I figured using a unmanaged struct would
            // make things more interesting (and dangerous).
            progressData = (MAPPED_PROGRESS_DATA?)Marshal.PtrToStructure(mappedView.DangerousGetHandle(), typeof(MAPPED_PROGRESS_DATA));
            if (progressData is not null)
            {
                ProgressRecord record = new(0, progressData.Value.Action, progressData.Value.Status)
                {
                    PercentComplete = (int)progressData.Value.PercentComplete
                };
                WriteProgress(record);
            }
        }
    }

    // A wrapper for the memory mapped file.
    internal sealed class ProgressDataSharedMemory : IDisposable
    {
        // Using the singleton pattern.
        private static ProgressDataSharedMemory? _instance;
        
        // All views will be kept here to be properly disposed at the end.
        private readonly Dictionary<Guid, SafeMemoryMappedViewHandle> _mappedViews;
        
        // The memory mapped file safe handle.
        private readonly SafeMemoryMappedFileHandle _mappedFileHandle;
        
        // This might not be necessary, this value should be standard for x64 machines,
        // but I'm paranoid.
        private readonly uint _allocGranularity;
        
        // The total size of the memory mapped file.
        private readonly uint _size;

        private ProgressDataSharedMemory()
        {
            // Creating the mapping.
            _size = 1 << 20;
            _mappedFileHandle = NativeFunctions.CreateFileMapping(new SafeFileHandle(-1, true), IntPtr.Zero, 4, 0, _size, "AmazingFileMappedMemory");
            _mappedViews = new();

            // Getting the system allocation granularity.
            SYSTEM_INFO sysInfo = new();
            NativeFunctions.GetSystemInfo(ref sysInfo);
            _allocGranularity = sysInfo.dwAllocationGranularity;
        }

        // Returning the handle so we can pass to unmanaged code.
        // Views will be created there using this handle.
        internal IntPtr DangerousGetMappedFileHandle()
            => _mappedFileHandle.DangerousGetHandle();

        internal static ProgressDataSharedMemory GetMappedMemory()
        {
            _instance ??= new();
            return _instance;
        }

        // Mapping a view.
        internal SafeMemoryMappedViewHandle MapView(out Guid id, uint desiredAccess, ulong offset, uint numberBytes)
        {
            if (offset > numberBytes)
                throw new ArgumentOutOfRangeException(nameof(offset));

            if (numberBytes == 0)
                throw new ArgumentOutOfRangeException(nameof(numberBytes));

            // The maximum bytes number returned is the size of the mapped file.
            numberBytes =  numberBytes > _size ? _size : numberBytes;

            // The offset needs to be a multiple of the system allocation granularity.
            // If it's not, we round to the closest value.
            ulong remainder = offset % _allocGranularity;
            if (remainder != 0)
            {
                offset -= remainder;
                if (remainder >= (_allocGranularity / 2))
                    offset += _allocGranularity;

            }

            // Converting the Int64 to a 'LARGE_INTEGER' style.
            uint offHigh = (uint)(offset & 0xFFFFFFFF00000000);
            uint offLow = (uint)(offset & 0xFFFFFFFF);

            // Mapping the view.
            SafeMemoryMappedViewHandle mappedView = NativeFunctions.MapViewOfFile(_mappedFileHandle, desiredAccess, offHigh, offLow, numberBytes);
            id = Guid.NewGuid();
            _mappedViews.Add(id, mappedView);

            return mappedView;
        }

        internal void UnmapView(Guid id)
        {
            if (_mappedViews.TryGetValue(id, out SafeMemoryMappedViewHandle? mappedView))
            {
                if (mappedView is not null && !mappedView.IsClosed && !mappedView.IsInvalid)
                    mappedView.Dispose();

                _mappedViews.Remove(id);
            }
        }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (disposing)
            {
                foreach (var mappedView in _mappedViews)
                    if (!mappedView.Value.IsClosed && !mappedView.Value.IsInvalid)
                        mappedView.Value.Dispose();

                _mappedFileHandle.Dispose();
            }
        }
    }

    internal partial class NativeFunctions
    {
        [LibraryImport("Kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16, EntryPoint = "CreateFileMappingW")]
        internal static partial SafeMemoryMappedFileHandle CreateFileMapping(
            SafeFileHandle hFile,
            IntPtr lpFileMappingAttributes,
            uint flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName
        );

        [LibraryImport("Kernel32.dll", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
        internal static partial SafeMemoryMappedViewHandle MapViewOfFile(
            SafeMemoryMappedFileHandle hFileMappingObject,
            uint dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            uint dwNumberOfBytesToMap
        );

        [LibraryImport("Kernel32.dll", SetLastError =true, StringMarshalling = StringMarshalling.Utf16)]
        internal static partial void GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);
    }

    // A struct representation of the unmanaged typedef struct.
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct MAPPED_PROGRESS_DATA
    {
        [MarshalAs(UnmanagedType.LPWStr)] internal string Action;
        [MarshalAs(UnmanagedType.LPWStr)] internal string Status;
        internal uint PercentComplete;
    }

    // We don't use this here, but if you want to set special permissions to the
    // memory mapped file this is one of the structs necessary.
    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES
    {
        internal uint nLength;
        IntPtr lpSecurityDescriptor;
        bool bInheritHandle;
    }

    // Used by 'GetSystemInfo'.
    [StructLayout(LayoutKind.Explicit)]
    internal struct SYSTEM_INFO
    {
        [FieldOffset(0x0)] internal uint dwOemId;
        [FieldOffset(0x0)] internal ushort wProcessorArchitecture;
        [FieldOffset(0x2)] internal ushort wReserved;
        [FieldOffset(0x4)] internal uint dwPageSize;
        [FieldOffset(0x8)] internal IntPtr lpMinimumApplicationAddress;
        [FieldOffset(0x10)] internal IntPtr lpMaximumApplicationAddress;
        [FieldOffset(0x18)] internal ulong dwActiveProcessorMask;
        [FieldOffset(0x20)] internal uint dwNumberOfProcessors;
        [FieldOffset(0x24)] internal uint dwProcessorType;
        [FieldOffset(0x28)] internal uint dwAllocationGranularity;
        [FieldOffset(0x2C)] internal ushort wProcessorLevel;
        [FieldOffset(0x2E)] internal ushort wProcessorRevision;
    }
}