/*
    File: DebuggerEngine.h
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 21/07/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DEBUGGERENGINE_H
#define DEBUGGERENGINE_H
#include <QMainWindow>
#include <windows.h>

class DebuggerEngine {

private:
    HANDLE m_hProcess;
    DWORD m_dwProcess;
    std::string m_processName;

public:
    DebuggerEngine(std::pair<DWORD, std::string> processInfo);
};

#endif // DEBUGGERENGINE_H
