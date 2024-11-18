/*
    File: DebugMemory.cc
    Author: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "debugmemory.hh"

DebugMemory::DebugMemory(uintptr_t uipStartAddress, QString strInformation, QString strType, QString strState, QString strProtection, size_t szPage)
: m_uipStartAddress(uipStartAddress), m_strInformation(strInformation), m_strType(strType), m_strState(strState), m_strProtection(strProtection),
m_szPage(szPage) {}
