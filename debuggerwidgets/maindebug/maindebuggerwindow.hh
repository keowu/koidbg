/*
    File: MainDebuggerWindow.hh
    Authors: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 01/12/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef MAINDEBUGGERWINDOW_H
#define MAINDEBUGGERWINDOW_H

#include <QMainWindow>
#include <QHeaderView>
#include <QMessageBox>
#include <KurumiParser.hh>
#include "debuggerengine/DebuggerEngine.hh"

QT_BEGIN_NAMESPACE
namespace Ui {
class MainDebuggerWindow;
}
QT_END_NAMESPACE

class MainDebuggerWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainDebuggerWindow(QWidget *parent = nullptr);
    ~MainDebuggerWindow();


public slots:
    void onProcessAttachSelected(const std::pair<int, std::string>& process);

private slots:
    void onOpenExecutableClicked();
    void onAttachProcessClicked();
    void onRunDebug();
    void onStepOut();
    void onStepOver();
    void onStepIn();
    void onStopDebug();
    void onAbout();
    void onExitClicked();
    auto OnInterruptListRowClicked(const QModelIndex &index) -> void;
    auto OnCommandSendClicked() -> void;
    auto OnCommandClearClicked() -> void;
    auto OnLoadPdbClicked() -> void;
    auto OnClearPdbClicked() -> void;
    auto onRegisterClicked(const QModelIndex &index) -> void;
    auto onUserTabChangedClick(int index) -> void;
    auto onPdbFunctionClicked(const QModelIndex &index) -> void;
    void onThemeColorModeClicked();
    auto onMemoryPatchs() -> void;
    auto onExportPatchs() -> void;
    auto onImportPatchs() -> void;
    auto onProcessorFeatures() -> void;

private:
    Ui::MainDebuggerWindow *ui;
    DebuggerEngine *m_dbgEngine;
    bool m_isDarkModeEnabled{ FALSE };
};
#endif // MAINDEBUGGERWINDOW_H
