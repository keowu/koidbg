/*
    File: MainDebuggerWindow.h
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 14/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef MAINDEBUGGERWINDOW_H
#define MAINDEBUGGERWINDOW_H

#include <QMainWindow>
#include <QHeaderView>
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
    void onStopDebug();
    void onExitClicked();

private:
    Ui::MainDebuggerWindow *ui;
    DebuggerEngine *m_dbgEngine;
};
#endif // MAINDEBUGGERWINDOW_H
