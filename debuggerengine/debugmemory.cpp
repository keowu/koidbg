#include "debugmemory.h"

DebugMemory::DebugMemory(uintptr_t uipStartAddress, QString strInformation, QString strType, QString strState, QString strProtection, size_t szPage)
: m_uipStartAddress(uipStartAddress), m_strInformation(strInformation), m_strType(strType), m_strState(strState), m_strProtection(strProtection),
m_szPage(szPage) {}
