/*
    File: DebugThread.hh
    Author: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 08/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DEBUGTHREAD_H
#define DEBUGTHREAD_H
#include <QMainWindow>
#include <windows.h>

class DebugThread {

public:

    HANDLE m_hThread;
    HANDLE m_ThreadID;
    uintptr_t m_lpThreadLocalBase;
    uintptr_t m_lpStartAddress;
    uintptr_t m_teb;
    int m_priorityLevel;

    DebugThread(HANDLE hThread, HANDLE ThreadID, uintptr_t lpThreadLocalBase, uintptr_t lpStartAddress, uintptr_t teb, int priorityLevel);

    auto getPriorityLevelToString() -> QString;

};

#endif // DEBUGTHREAD_H
