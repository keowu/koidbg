/*
    File: DebugBreakpoints.h
    Author: João Vitor(@Keowu)
    Created: 11/08/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DEBUGBREAKPOINT_H
#define DEBUGBREAKPOINT_H
#include <QMainWindow>
#include <windows.h>

enum InterruptType {

    BREAK_HW,
    BREAK_INT

};

class DebugBreakpoint {

public:    
    uintptr_t m_ptrBreakpointAddress;
    unsigned char* m_ucOriginalOpcodes;
    size_t m_szOriginalOpcodes;
    //Tipo de interrupção: HW(Hardware), INT3(Software) or SEH(Interrupt)
    InterruptType m_intType;

    DebugBreakpoint(uintptr_t ptrBreakpointAddress, unsigned char* ucOriginalOpcodes, size_t szOriginalOpcodes, InterruptType intType);
    ~DebugBreakpoint();


};

#endif // DEBUGBREAKPOINT_H
