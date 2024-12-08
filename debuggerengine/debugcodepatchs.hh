/*
    File: debugcodepatchs.hh
    Authors: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef DEBUGCODEPATCHS_HH
#define DEBUGCODEPATCHS_HH
#include <QMainWindow>
#include <windows.h>
#include "debugmodule.hh"

class DebugCodePatchs {

public:
    uintptr_t m_patchOffset;
    DebugModule m_module;
    std::vector<uint8_t> m_originalCode;
    std::vector<uint8_t> m_modifiedCode;

    DebugCodePatchs(DebugModule module, uintptr_t patchOffset,
                    const std::vector<uint8_t>& originalCode, const std::vector<uint8_t>& modifiedCode);
    ~DebugCodePatchs() { };

};

#endif // DEBUGCODEPATCHS_HH
