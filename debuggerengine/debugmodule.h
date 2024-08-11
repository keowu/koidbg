/*
    File: DebugModule.h
    Author: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 08/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DEBUGMODULE_H
#define DEBUGMODULE_H
#include <QMainWindow>
#include <windows.h>

class DebugModule {

public:
    HANDLE m_hModule;
    QString m_qStName;
    uintptr_t m_lpModuleBase;

    DebugModule(HANDLE hModule, QString qStName, uintptr_t lpModuleBase);

};

#endif // DEBUGMODULE_H
