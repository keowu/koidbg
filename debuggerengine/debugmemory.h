#ifndef DEBUGMEMORY_H
#define DEBUGMEMORY_H
#include <QMainWindow>
#include <windows.h>

class DebugMemory {

public:
    uintptr_t m_uipStartAddress;
    QString m_strInformation;
    QString m_strType;
    QString m_strState;
    QString m_strProtection;
    size_t m_szPage;

    DebugMemory(uintptr_t uipStartAddress, QString strInformation, QString strType, QString strState, QString strProtection, size_t szPage);

};

#endif // DEBUGMEMORY_H
