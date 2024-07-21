/*
    File: DisassemblerEngine.h
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 21/07/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef DISASSEMBLERENGINE_H
#define DISASSEMBLERENGINE_H
#include <QDebug>
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <capstone/platform.h>
#include <capstone/capstone.h>

struct platform {

    cs_arch arch;
    cs_mode mode;
    unsigned char *code;
    size_t size;
    const char *comment;
};

class DisassemblerEngine {


public:

    auto TestCapstoneEngine() -> void;
};

#endif // DISASSEMBLERENGINE_H
