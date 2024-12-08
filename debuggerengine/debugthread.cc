/*
    File: DebugThread.cc
    Authors: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#include "debugthread.hh"

auto DebugThread::getPriorityLevelToString() -> QString {

    if (this->m_priorityLevel == 1) return "THREAD_PRIORITY_ABOVE_NORMAL";
    else if (this->m_priorityLevel == -1) return "THREAD_PRIORITY_BELOW_NORMAL";
    else if (this->m_priorityLevel == 2) return "THREAD_PRIORITY_HIGHEST";
    else if (this->m_priorityLevel == -15) return "THREAD_PRIORITY_IDLE";
    else if (this->m_priorityLevel == -2) return "THREAD_PRIORITY_LOWEST";
    else if (this->m_priorityLevel == 0) return "THREAD_PRIORITY_NORMAL";
    else if (this->m_priorityLevel == 15) return "THREAD_PRIORITY_TIME_CRITICAL";

    return "THREAD_PRIORITY_UNKNOWN";
}


DebugThread::DebugThread(HANDLE hThread, HANDLE ThreadID, uintptr_t lpThreadLocalBase, uintptr_t lpStartAddress, uintptr_t teb, int priorityLevel)
    : m_hThread(hThread), m_ThreadID(ThreadID), m_lpThreadLocalBase(lpThreadLocalBase), m_lpStartAddress(lpStartAddress), m_teb(teb), m_priorityLevel(priorityLevel) { };
