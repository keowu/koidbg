/*
    File: utilswindowssycall.h
    Author: João Vitor(@Keowu)
    Created: 24/07/2024
    Last Update: 28/07/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef UTILSWINDOWSSYSCALL_H
#define UTILSWINDOWSSYSCALL_H
#include <Windows.h>
#include <Winternl.h>
#include <psapi.h>
#include <tchar.h>
#include <strsafe.h>
#include <QMainWindow>
#include <QtCore/QString>
#include <QtCore/QDebug>

typedef LONG KPRIORITY;

typedef struct _THREAD_BASIC_INFORMATION {

    NTSTATUS ExitStatus;
    PTEB TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;

} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

using tpdNtQueryInformationThread = NTSTATUS (__stdcall *)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

#define ThreadBasicInformation 0

namespace UtilsWindowsSyscall {

inline auto GetThreadBasicInformation(HANDLE hThread) -> std::unique_ptr<THREAD_BASIC_INFORMATION> {

    std::unique_ptr<THREAD_BASIC_INFORMATION> tbi = std::make_unique<THREAD_BASIC_INFORMATION>();

    auto NtQueryInformationThread = reinterpret_cast<tpdNtQueryInformationThread>(GetProcAddress(LoadLibraryA("ntdll.dll"), "NtQueryInformationThread"));

    NtQueryInformationThread(hThread, (THREADINFOCLASS)ThreadBasicInformation, tbi.get(), sizeof(THREAD_BASIC_INFORMATION), nullptr);

    return tbi;
}

inline auto GetFileNameFromHandle(HANDLE hFile) -> QString {
    QString fileName;
    TCHAR pszFilename[MAX_PATH + 1];
    HANDLE hFileMap;

    // Get the file size.
    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi);

    if (dwFileSizeLo == 0 && dwFileSizeHi == 0) {

        fileName = QString("Cannot map a file with a length of zero.");

        return fileName;
    }

    // Create a file mapping object.
    hFileMap = CreateFileMapping(hFile,
                                 NULL,
                                 PAGE_READONLY,
                                 0,
                                 1,
                                 NULL);

    if (hFileMap) {

        // Create a file mapping to get the file name.
        void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

        if (pMem) {

            if (GetMappedFileName(GetCurrentProcess(),
                                  pMem,
                                  pszFilename,
                                  MAX_PATH)) {

                // Translate path with device name to drive letters.
                TCHAR szTemp[MAX_PATH];
                szTemp[0] = '\0';

                if (GetLogicalDriveStrings(MAX_PATH - 1, szTemp)) {

                    TCHAR szName[MAX_PATH];
                    TCHAR szDrive[3] = TEXT(" :");
                    BOOL bFound = FALSE;
                    TCHAR* p = szTemp;

                    do {
                        // Copy the drive letter to the template string
                        *szDrive = *p;

                        // Look up each device name
                        if (QueryDosDevice(szDrive, szName, MAX_PATH)) {

                            size_t uNameLen = _tcslen(szName);

                            if (uNameLen < MAX_PATH) {

                                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0
                                         && *(pszFilename + uNameLen) == L'\\';

                                if (bFound) {

                                    // Reconstruct pszFilename using szTempFile
                                    // Replace device path with DOS path
                                    TCHAR szTempFile[MAX_PATH];
                                    StringCchPrintf(szTempFile,
                                                    MAX_PATH,
                                                    TEXT("%s%s"),
                                                    szDrive,
                                                    pszFilename + uNameLen);
                                    StringCchCopyN(pszFilename, MAX_PATH + 1, szTempFile, _tcslen(szTempFile));
                                }
                            }
                        }

                        // Go to the next NULL character.
                        while (*p++);
                    } while (!bFound && *p); // end of string
                }
            }
            fileName = QString::fromWCharArray(pszFilename);
            UnmapViewOfFile(pMem);
        }

        CloseHandle(hFileMap);
    }

    return fileName;
}



};

#endif // UTILSWINDOWSSYSCALL_H
