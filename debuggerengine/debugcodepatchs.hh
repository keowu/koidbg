/*
    File: debugcodepatchs.hh
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DEBUGCODEPATCHS_HH
#define DEBUGCODEPATCHS_HH
#include <QMainWindow>
#include <windows.h>

class debugcodepatchs {

private:
    uintptr_t m_patchOffset;
    std::string m_moduleName;
    std::vector<uint8_t> m_originalCode;
    std::vector<uint8_t> m_modifiedCode;

public:
    debugcodepatchs(uintptr_t patchOffset, const std::string& moduleName,
                    const std::vector<uint8_t>& originalCode, const std::vector<uint8_t>& modifiedCode);
    ~debugcodepatchs();

};

#endif // DEBUGCODEPATCHS_HH
