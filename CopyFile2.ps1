try {
    Add-Type -TypeDefinition @'
namespace Utilities {
    using System;
    using System.Text;
    using System.Runtime.InteropServices;

    public delegate COPYFILE2_MESSAGE_ACTION CopyFile2ProgressRoutine(
        [In] COPYFILE2_MESSAGE pMessage,
        [In, Optional] IntPtr pvCallbackContext
    );

    [Flags]
    public enum CopyFlags : uint {
        COPY_FILE_FAIL_IF_EXISTS = 0x00000001,
        COPY_FILE_RESTARTABLE = 0x00000002,
        COPY_FILE_OPEN_SOURCE_FOR_WRITE = 0x00000004,
        COPY_FILE_ALLOW_DECRYPTED_DESTINATION = 0x00000008,
        COPY_FILE_COPY_SYMLINK = 0x00000800,
        COPY_FILE_NO_BUFFERING = 0x00001000,
        COPY_FILE_REQUEST_SECURITY_PRIVILEGES = 0x00002000,
        COPY_FILE_RESUME_FROM_PAUSE = 0x00004000,
        COPY_FILE_NO_OFFLOAD = 0x00040000,
        COPY_FILE_REQUEST_COMPRESSED_TRAFFIC = 0x10000000
    }
    
    public enum COPYFILE2_MESSAGE_ACTION : uint {
        COPYFILE2_PROGRESS_CONTINUE,
        COPYFILE2_PROGRESS_CANCEL,
        COPYFILE2_PROGRESS_STOP,
        COPYFILE2_PROGRESS_QUIET,
        COPYFILE2_PROGRESS_PAUSE
    }

    public enum COPYFILE2_MESSAGE_TYPE : uint {
        COPYFILE2_CALLBACK_NONE,
        COPYFILE2_CALLBACK_CHUNK_STARTED,
        COPYFILE2_CALLBACK_CHUNK_FINISHED,
        COPYFILE2_CALLBACK_STREAM_STARTED,
        COPYFILE2_CALLBACK_STREAM_FINISHED,
        COPYFILE2_CALLBACK_POLL_CONTINUE,
        COPYFILE2_CALLBACK_ERROR,
        COPYFILE2_CALLBACK_MAX
    }

    public enum COPYFILE2_COPY_PHASE : uint {
        COPYFILE2_PHASE_NONE,
        COPYFILE2_PHASE_PREPARE_SOURCE,
        COPYFILE2_PHASE_PREPARE_DEST,
        COPYFILE2_PHASE_READ_SOURCE,
        COPYFILE2_PHASE_WRITE_DESTINATION,
        COPYFILE2_PHASE_SERVER_COPY,
        COPYFILE2_PHASE_NAMEGRAFT_COPY,
        COPYFILE2_PHASE_MAX
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct ULARGE_INTEGER {
        public Int64 QuadPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _ChunkStarted {
        public uint          dwStreamNumber;
        public uint          dwReserved;
        public IntPtr         hSourceFile;
        public IntPtr         hDestinationFile;
        public ULARGE_INTEGER uliChunkNumber;
        public ULARGE_INTEGER uliChunkSize;
        public ULARGE_INTEGER uliStreamSize;
        public ULARGE_INTEGER uliTotalFileSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _ChunkFinished {
        public uint          dwStreamNumber;
        public uint          dwFlags;
        public IntPtr         hSourceFile;
        public IntPtr         hDestinationFile;
        public ULARGE_INTEGER uliChunkNumber;
        public ULARGE_INTEGER uliChunkSize;
        public ULARGE_INTEGER uliStreamSize;
        public ULARGE_INTEGER uliStreamBytesTransferred;
        public ULARGE_INTEGER uliTotalFileSize;
        public ULARGE_INTEGER uliTotalBytesTransferred;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _StreamStarted {
        public uint          dwStreamNumber;
        public uint          dwReserved;
        public IntPtr         hSourceFile;
        public IntPtr         hDestinationFile;
        public ULARGE_INTEGER uliStreamSize;
        public ULARGE_INTEGER uliTotalFileSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _StreamFinished {
        public uint          dwStreamNumber;
        public uint          dwReserved;
        public IntPtr         hSourceFile;
        public IntPtr         hDestinationFile;
        public ULARGE_INTEGER uliStreamSize;
        public ULARGE_INTEGER uliStreamBytesTransferred;
        public ULARGE_INTEGER uliTotalFileSize;
        public ULARGE_INTEGER uliTotalBytesTransferred;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _PollContinue {
        public uint dwReserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct _Error {
        COPYFILE2_COPY_PHASE CopyPhase;
        uint                dwStreamNumber;
        IntPtr              hrFailure;
        uint                dwReserved;
        ULARGE_INTEGER       uliChunkNumber;
        ULARGE_INTEGER       uliStreamSize;
        ULARGE_INTEGER       uliStreamBytesTransferred;
        ULARGE_INTEGER       uliTotalFileSize;
        ULARGE_INTEGER       uliTotalBytesTransferred;
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct COPYFILE2_MESSAGE {
        [FieldOffset(0)]
        public COPYFILE2_MESSAGE_TYPE Type;

        [FieldOffset(1)]
        public uint dwPadding;

        [FieldOffset(2)]
        public _ChunkStarted ChunkStarted;

        [FieldOffset(2)]
        public _ChunkFinished ChunkFinished;

        [FieldOffset(2)]
        public _StreamStarted StreamStarted;

        [FieldOffset(2)]
        public _StreamFinished StreamFinished;

        [FieldOffset(2)]
        public _PollContinue PollContinue;

        [FieldOffset(2)]
        public _Error Error;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct COPYFILE2_EXTENDED_PARAMETERS {
        public uint dwSize;
        public CopyFlags dwCopyFlags;
        public bool pfCancel;
        public CopyFile2ProgressRoutine pProgressRoutine;
        public IntPtr pvCallbackContext;
    }

    public class FileSystem {

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern uint CopyFile2(
            string pwszExistingFileName,
            string pwszNewFileName,
            COPYFILE2_EXTENDED_PARAMETERS pExtendedParameters
        );

        public static void CopyFileEx(string filePath, string destination, Func<COPYFILE2_MESSAGE, IntPtr, COPYFILE2_MESSAGE_ACTION> callback) {
            COPYFILE2_EXTENDED_PARAMETERS extParams = new();
            extParams.dwSize = Convert.ToUInt32(Marshal.SizeOf(extParams));
            extParams.dwCopyFlags = CopyFlags.COPY_FILE_NO_BUFFERING | CopyFlags.COPY_FILE_COPY_SYMLINK;
            extParams.pProgressRoutine = new CopyFile2ProgressRoutine(callback);
            extParams.pvCallbackContext = IntPtr.Zero;

            uint result = CopyFile2(filePath, destination, extParams);
            if (result != 0)
                throw new SystemException(result.ToString());
        }
    }
}
'@
}
catch { }

[Func[
    Utilities.COPYFILE2_MESSAGE,
    IntPtr,
    Utilities.COPYFILE2_MESSAGE_ACTION
]]$delegate = {

    param([Utilities.COPYFILE2_MESSAGE]$message, $extArgs, $result)

    if ($message.Type -eq [Utilities.COPYFILE2_MESSAGE_TYPE]::COPYFILE2_CALLBACK_CHUNK_FINISHED) {
        Write-Progress -Activity 'Copying file.' -Status 'Copying...' -PercentComplete (($message.ChunkFinished.uliTotalFileSize.QuadPart / $message.ChunkFinished.uliStreamBytesTransferred.QuadPart) * 100)
    }
}

if (Test-Path -Path C:\CopyFile2TestDestination -PathType Container) { [void](mkdir C:\CopyFile2TestDestination) }
[Utilities.FileSystem]::CopyFileEx('C:\superTest.dat', 'C:\CopyFile2TestDestination\superTestCopy.dat', $delegate)
