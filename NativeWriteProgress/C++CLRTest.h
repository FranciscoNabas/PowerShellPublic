#pragma once

#pragma unmanaged
#include "Unmanaged.h"

#pragma managed
using namespace System;
using namespace System::Runtime::InteropServices;

#include <vcclr.h>

namespace CCLRTest {
	public ref class Wrapper
	{
	public:
		delegate void WrappedWriteProgress(UInt64 dataSize);

		void WriteProgress(WrappedWriteProgress^ wpDelegate, IntPtr mappedFile, String^ action, String^ status, UInt32 percentComplete)
		{
			pin_ptr<const wchar_t> wAction = PtrToStringChars(action);
			pin_ptr<const wchar_t> wStatus = PtrToStringChars(status);
			
			GCHandle gch = GCHandle::Alloc(wpDelegate);
			IntPtr delegatePtr = Marshal::GetFunctionPointerForDelegate(wpDelegate);
			Unmanaged::UnmanagedWriteProgress wrappedDel = static_cast<Unmanaged::UnmanagedWriteProgress>(delegatePtr.ToPointer());

			unmPtr->Unmanaged::WriteProgress(wrappedDel, (HANDLE)mappedFile.ToPointer(), (LPWSTR)wAction, (LPWSTR)wStatus, (DWORD)percentComplete);
		}

	private:
		Unmanaged* unmPtr;
	};
}