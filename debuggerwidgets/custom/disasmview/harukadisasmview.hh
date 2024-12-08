/*
    File: harukadisasmview.hh
    Authors: João Vitor(@Keowu)
    Created: 24/08/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef HARUKADISASMVIEW_H
#define HARUKADISASMVIEW_H

#include <QTableView>
#include <QContextMenuEvent>
#include <QMenu>
#include <QScrollBar>
#include <Windows.h>
#include "debuggerwidgets/custom/qhexview/QHexView.hh"
#include "decompiler/decompiler.hh"

using BreakPointCallback = std::function<void(uintptr_t, bool)>;
using SetIPCallback = std::function<void(uintptr_t)>;
using SetPatching = std::function<void(std::string, uintptr_t, const std::vector<uint8_t>&, const std::vector<uint8_t>&)>;

class HarukaDisasmView : public QTableView {
    Q_OBJECT

public:
    explicit HarukaDisasmView(QWidget *parent = nullptr);
    auto configureDisasm(QHexView* qHexVw[3], QTextEdit* txtDecompiler, QTabWidget* qTabHaruka, HANDLE hProcessInternal, BreakPointCallback setBreakPointCallback, SetIPCallback setIPCallback, SetPatching setPatching) -> void;

protected:
    void contextMenuEvent(QContextMenuEvent *event) override;

private:
    QHexView* m_qHexVw[3];
    QTextEdit* m_txtDecompiler;
    QTabWidget* m_qTabHaruka;
    HANDLE m_hProcessInternal;
    BreakPointCallback m_setBreakPointCallback;
    SetIPCallback m_setIPCallback;
    SetPatching m_setPatchingCallback;
    Decompiler* m_decompilerSyntax = { nullptr };

    auto updateMemoryInspector(QHexView* memoryInspector, QString addressString) -> void;

private slots:
    void onSoftwareInterrupt();
    void onHardwareInterrupt();
    void onMemoryInspector1();
    void onMemoryInspector2();
    void onMemoryInspector3();
    void onActionSetIp();
    void onDecompileToPseudoC();
    void onPatchCode();

};

#endif // HARUKADISASMVIEW_H
