/*
    File: DebugModule.hh
    Authors: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
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
    DebugModule(){ };

};

#endif // DEBUGMODULE_H
