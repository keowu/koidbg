/*
    File: DebugHandles.hh
    Authors: João Vitor(@Keowu)
    Created: 08/08/2024
    Last Update: 12/08/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef DEBUGHANDLE_H
#define DEBUGHANDLE_H
#include <QMainWindow>
#include <windows.h>

class DebugHandle {

public:
    HANDLE m_hValue;
    QString m_strType;
    QString m_strName;
    size_t m_szType;
    size_t m_szName;

    DebugHandle(HANDLE hValue, QString strType, QString strName, size_t szType, size_t szName);

};

#endif // DEBUGHANDLE_H
