using CCLRTest;
using Microsoft.Win32.SafeHandles;
using System.Management.Automation;
using System.Runtime.InteropServices;

namespace Testing;

public class TestConsole : PSCmdlet
{
    private static readonly ProgressDataSharedMemory _sharedProgressData = ProgressDataSharedMemory.GetMappedMemory();

    public static void Main(string[] args)
    {
        Wrapper unw = new();
        Wrapper.WrappedWriteProgress wpfunc = new(WriteProgressAction);

        for (uint i = 0; i < 100; i++)
        {
            Thread.Sleep(100);
            unw.WriteProgress(wpfunc, _sharedProgressData.DangerousGetMappedFileHandle(), "Testing progress", "Counting...", i);
        }
    }

    private static void WriteProgressAction(ulong dataSize)
    {
        MAPPED_PROGRESS_DATA? progressData;
        SafeMemoryMappedViewHandle mappedView = _sharedProgressData.MapView(out Guid viewId, 4, 0, (uint)dataSize);

        progressData = (MAPPED_PROGRESS_DATA?)Marshal.PtrToStructure(mappedView.DangerousGetHandle(), typeof(MAPPED_PROGRESS_DATA));
        if (progressData is not null)
        {
            ProgressRecord record = new(0, progressData.Value.Action, progressData.Value.Status);
            record.PercentComplete = (int)progressData.Value.PercentComplete;
            Console.WriteLine(record);
        }
    }
}

internal sealed class ProgressDataSharedMemory : IDisposable
{
    private static ProgressDataSharedMemory? _instance;
    private readonly Dictionary<Guid, SafeMemoryMappedViewHandle> _mappedViews;
    private readonly SafeMemoryMappedFileHandle _mappedFileHandle;
    private readonly uint _allocGranularity;
    private readonly uint _size;

    private ProgressDataSharedMemory()
    {
        _size = 1 << 20;
        _mappedFileHandle = NativeFunctions.CreateFileMapping(new SafeFileHandle(-1, true), IntPtr.Zero, 4, 0, _size, "AmazingFileMappedMemory");
        _mappedViews = new();

        SYSTEM_INFO sysInfo = new();
        NativeFunctions.GetSystemInfo(ref sysInfo);
        _allocGranularity = sysInfo.dwAllocationGranularity;
    }

    internal IntPtr DangerousGetMappedFileHandle()
        => _mappedFileHandle.DangerousGetHandle();

    internal static ProgressDataSharedMemory GetMappedMemory()
    {
        _instance ??= new();
        return _instance;
    }

    internal SafeMemoryMappedViewHandle MapView(out Guid id, uint desiredAccess, ulong offset, uint numberBytes)
    {
        if (numberBytes == 0)
            throw new ArgumentOutOfRangeException(nameof(numberBytes));

        // The maximum bytes number returned is the size of the mapped file.
        numberBytes = numberBytes > _size ? _size : numberBytes;

        // The offset needs to be a multiple of the system allocation granularity.
        // If it's not, we round to the closest value.
        ulong remainder = offset % _allocGranularity;
        if (remainder != 0)
        {
            offset -= remainder;
            if (remainder >= (_allocGranularity / 2))
                offset += _allocGranularity;

        }

        uint offHigh = (uint)(offset & 0xFFFFFFFF00000000);
        uint offLow = (uint)(offset & 0xFFFFFFFF);

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
    [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileMappingW")]
    internal static extern SafeMemoryMappedFileHandle CreateFileMapping(
        SafeFileHandle hFile,
        IntPtr lpFileMappingAttributes,
        uint flProtect,
        uint dwMaximumSizeHigh,
        uint dwMaximumSizeLow,
        string lpName
    );

    [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern SafeMemoryMappedViewHandle MapViewOfFile(
        SafeMemoryMappedFileHandle hFileMappingObject,
        uint dwDesiredAccess,
        uint dwFileOffsetHigh,
        uint dwFileOffsetLow,
        uint dwNumberOfBytesToMap
    );

    [DllImport("Kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern void GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct MAPPED_PROGRESS_DATA
{
    [MarshalAs(UnmanagedType.LPWStr)] internal string Action;
    [MarshalAs(UnmanagedType.LPWStr)] internal string Status;
    internal uint PercentComplete;
}

[StructLayout(LayoutKind.Sequential)]
internal struct SECURITY_ATTRIBUTES
{
    internal uint nLength;
    IntPtr lpSecurityDescriptor;
    bool bInheritHandle;
}

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