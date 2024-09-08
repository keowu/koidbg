/*
    File: harukadisasmview.h
    Author: João Vitor(@Keowu)
    Created: 24/08/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef HARUKADISASMVIEW_H
#define HARUKADISASMVIEW_H

#include <QTableView>
#include <QContextMenuEvent>
#include <QMenu>
#include <Windows.h>
#include "debuggerwidgets/custom/qhexview/QHexView.hpp"

using BreakPointCallback = std::function<void(uintptr_t, bool)>;
using SetIPCallback = std::function<void(uintptr_t)>;

class HarukaDisasmView : public QTableView {
    Q_OBJECT

public:
    explicit HarukaDisasmView(QWidget *parent = nullptr);
    auto configureDisasm(QHexView* qHexVw[3], HANDLE hProcessInternal, BreakPointCallback setBreakPointCallback, SetIPCallback setIPCallback) -> void;

protected:
    void contextMenuEvent(QContextMenuEvent *event) override;

private:
    QHexView* m_qHexVw[3];
    HANDLE m_hProcessInternal;
    BreakPointCallback m_setBreakPointCallback;
    SetIPCallback m_setIPCallback;

    auto updateMemoryInspector(QHexView* memoryInspector, QString addressString) -> void;

private slots:
    void onSoftwareInterrupt();
    void onHardwareInterrupt();
    void onMemoryInspector1();
    void onMemoryInspector2();
    void onMemoryInspector3();
    void onActionSetIp();
    void onDecompileToPseudoC();

};

#endif // HARUKADISASMVIEW_H
