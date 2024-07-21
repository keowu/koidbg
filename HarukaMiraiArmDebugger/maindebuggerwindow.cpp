/*
    File: MainDebuggerWindow.cpp
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 21/07/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "maindebuggerwindow.h"
#include "./ui_maindebuggerwindow.h"
#include "attachprocesswindow.h"
#include "disassemblerengine.h"
#include <windows.h>
#include <QDebug>
#include <QFileDialog>

MainDebuggerWindow::MainDebuggerWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainDebuggerWindow)
{
    ui->setupUi(this);

    connect(ui->btnOpenExecutable, &QAction::triggered, this, &MainDebuggerWindow::onOpenExecutableClicked);
    connect(ui->btnAttachProcessContainer, &QAction::triggered, this, &MainDebuggerWindow::onAttachProcessClicked);
    connect(ui->btnDebugDynamicLibrary, &QAction::triggered, this, &MainDebuggerWindow::onDebugDynamicLibraryClicked);
    connect(ui->btnExit, &QAction::triggered, this, &MainDebuggerWindow::onExitClicked);
    
}

void MainDebuggerWindow::onOpenExecutableClicked() {

    auto filePath = QFileDialog::getOpenFileName(this, "Open File", "", "Executable Files (*.exe);;All Files (*)");

    if (filePath.isEmpty()) {

        ui->statusbar->showMessage("[No Executable Selected]: Please, select a \".exe\" to continue.", 1000);

        return;
    }

    STARTUPINFOEXW si;
    ZeroMemory(&si, sizeof(si));
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::wstring filePathWStr = filePath.toStdWString();

    std::wstring cmdLine = filePathWStr + L" ";
    wchar_t* cmdLineMutable = &cmdLine[0];

    BOOL ret = CreateProcessW(

        NULL,
        cmdLineMutable,
        NULL,
        NULL,
        FALSE,
        DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi

    );

    if (!ret) {

        ui->statusbar->showMessage("[ERROR CreateProcessW]: 0x" + QString::number(GetLastError(), 16), 1000);

        return;
    }

    //Testing
    DisassemblerEngine *disasm = new DisassemblerEngine();
    disasm->TestCapstoneEngine();
    delete disasm;
}

void MainDebuggerWindow::onAttachProcessClicked() {

    auto attach = new AttachProcessWindow();

    // Attaching to receive signal with selected process pid
    connect(attach, &AttachProcessWindow::onProcessSelectedAttach, this, &MainDebuggerWindow::onProcessAttachSelected);

    attach->show();

}

void MainDebuggerWindow::onDebugDynamicLibraryClicked() {

    qDebug() << "Hello World !";

}

void MainDebuggerWindow::onExitClicked() {

    this->close();

}

void MainDebuggerWindow::onProcessAttachSelected(const std::pair<int, std::string>& process) {

    qDebug() << "Received: " << process.second << " " << QString::number(process.first);

    this->m_dbgEngine = new DebuggerEngine(process);

}

MainDebuggerWindow::~MainDebuggerWindow()
{
    delete ui;
}
