/*
    File: debugcodepatchs.cc
    Authors: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#include "debugcodepatchs.hh"

DebugCodePatchs::DebugCodePatchs(DebugModule module, uintptr_t patchOffset,
                                 const std::vector<uint8_t>& originalCode, const std::vector<uint8_t>& modifiedCode) :
    m_patchOffset(patchOffset), m_module(module), m_originalCode(originalCode),
    m_modifiedCode(modifiedCode) { };
