/*
    File: DebugHandles.cpp
    Author: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "debughandle.hh"

DebugHandle::DebugHandle(HANDLE hValue, QString strType, QString strName, size_t szType, size_t szName)
: m_hValue(hValue), m_strType(strType), m_strName(strName), m_szType(szType), m_szName(szName) {}
