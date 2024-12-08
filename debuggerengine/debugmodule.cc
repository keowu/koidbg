/*
    File: DebugModule.cc
    Authors: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#include "debugmodule.hh"

DebugModule::DebugModule(HANDLE hModule, QString qStName, uintptr_t lpModuleBase) : m_hModule(hModule), m_qStName(qStName), m_lpModuleBase(lpModuleBase) { }
