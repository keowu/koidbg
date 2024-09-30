/*
    File: MainDebuggerWindow.h
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 29/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef MAINDEBUGGERWINDOW_H
#define MAINDEBUGGERWINDOW_H

#include <QMainWindow>
#include <QHeaderView>
#include <QMessageBox>
#include "debuggerengine/DebuggerEngine.h"

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
    void onDebugDynamicLibraryClicked();
    void onRunDebug();
    void onStepOut();
    void onStepOver();
    void onStepIn();
    void onStopDebug();
    void onAbout();
    void onExitClicked();
    auto OnInterruptListRowClicked(const QModelIndex &index) -> void;
    auto OnCommandSendClicked() -> void;

private:
    Ui::MainDebuggerWindow *ui;
    DebuggerEngine *m_dbgEngine;
};
#endif // MAINDEBUGGERWINDOW_H
