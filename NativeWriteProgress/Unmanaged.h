#pragma once

#pragma unmanaged

#include <Windows.h>

#define MAPPED_MEMORY_NAME L"AmazingFileMappedMemory"

namespace CCLRTest {
	extern "C" public class __declspec(dllexport) Unmanaged {
	public:
		typedef struct _MAPPED_PROGRESS_DATA
		{
			LPWSTR Action;
			LPWSTR Status;
			DWORD PercentComplete;

			_MAPPED_PROGRESS_DATA(LPWSTR const& action, LPWSTR const& status, DWORD percentComplete)
			{
				size_t szAction = wcslen(action) + 1;
				size_t szStatus = wcslen(status) + 1;

				Action = new WCHAR[szAction];
				Status = new WCHAR[szStatus];

				wcscpy_s(Action, szAction, action);
				wcscpy_s(Status, szStatus, status);

				PercentComplete = percentComplete;
			}

			~_MAPPED_PROGRESS_DATA()
			{
				delete[] Action;
				delete[] Status;
			}

		} MAPPED_PROGRESS_DATA, *PMAPPED_PROGRESS_DATA;

		typedef void(__stdcall* UnmanagedWriteProgress)(size_t dataSize);

		void WriteProgress(UnmanagedWriteProgress fp, HANDLE mappedFile, LPWSTR const& action, LPWSTR const& status, DWORD percentComplete)
		{
			MAPPED_PROGRESS_DATA progressData = { action, status, percentComplete };
			size_t szData = sizeof(progressData);
			
			LPVOID mappedView = MapViewOfFile(mappedFile, FILE_MAP_WRITE, 0, 0, szData);
			if (mappedView != NULL)
				*((PMAPPED_PROGRESS_DATA)mappedView) = progressData;

			UnmapViewOfFile(mappedView);

			return fp(szData);
		}
	};
}