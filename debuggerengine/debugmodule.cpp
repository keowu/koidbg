/*
    File: DebugModule.cpp
    Author: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 08/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "debugmodule.h"

DebugModule::DebugModule(HANDLE hModule, QString qStName, uintptr_t lpModuleBase) : m_hModule(hModule), m_qStName(qStName), m_lpModuleBase(lpModuleBase) { }
