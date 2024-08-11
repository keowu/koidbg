/*
    File: DebugBreakpoints.cpp
    Author: João Vitor(@Keowu)
    Created: 11/08/2024
    Last Update: 11/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "debugbreakpoint.h"

DebugBreakpoint::DebugBreakpoint(uintptr_t ptrBreakpointAddress, unsigned char* ucOriginalOpcodes, size_t szOriginalOpcodes, InterruptType intType) :
m_ptrBreakpointAddress(ptrBreakpointAddress), m_ucOriginalOpcodes(ucOriginalOpcodes), m_szOriginalOpcodes(szOriginalOpcodes), m_intType(intType) {}

DebugBreakpoint::~DebugBreakpoint() {

    delete this->m_ucOriginalOpcodes;

}
