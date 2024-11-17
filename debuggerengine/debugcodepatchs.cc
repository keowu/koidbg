/*
    File: debugcodepatchs.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "debugcodepatchs.hh"

debugcodepatchs::debugcodepatchs(uintptr_t patchOffset, const std::string& moduleName,
                                 const std::vector<uint8_t>& originalCode, const std::vector<uint8_t>& modifiedCode) :
    m_patchOffset(patchOffset), m_moduleName(moduleName), m_originalCode(originalCode),
    m_modifiedCode(modifiedCode) { };
