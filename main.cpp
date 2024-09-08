/*
    File: main.cpp
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "debuggerwidgets/maindebug/MainDebuggerWindow.h"
#include <QtWidgets/QApplication>
#include <QMessageBox>
#include <Shlobj.h>

auto elevateProcess() -> void {

    TCHAR szPath[MAX_PATH]{ 0 };

    if (GetModuleFileName(NULL, szPath, ARRAYSIZE(szPath))) {

        SHELLEXECUTEINFO sei;
        sei.cbSize = sizeof(sei);
        sei.lpVerb = TEXT("runas");
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteEx(&sei))

            QMessageBox::critical(NULL, "Error!", "HakuMirai needs admin privilege to run!");


        TerminateProcess(GetCurrentProcess(), 0);

    }

}

auto EnableDebugPrivilege() -> bool {

    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {

        CloseHandle(hToken);

        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {

        CloseHandle(hToken);

        return false;
    }

    CloseHandle(hToken);

    return true;

}

int main(int argc, char *argv[]) {

    /*if (!IsUserAnAdmin())
        elevateProcess();*/

    if (!EnableDebugPrivilege()) QMessageBox::critical(NULL, "No privilege", "HarukaMirai needs SeDebugPrivilege to run !");

    QApplication a(argc, argv);

    //Desativar todos os logs da aplicação.
    //QLoggingCategory::setFilterRules("*.debug=false\n"
    //                                 "*.warning=false\n"
    //                                 "*.info=false");

    MainDebuggerWindow w;

    w.show();

    return a.exec();
}
