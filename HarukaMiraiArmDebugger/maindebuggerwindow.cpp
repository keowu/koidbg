/*
    File: MainDebuggerWindow.cpp
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 04/08/2024

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

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
     */
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);
    setWindowFlags(Qt::MSWindowsFixedSizeDialogHint);

    /*
     * Slots
     */
    connect(ui->btnOpenExecutable, &QAction::triggered, this, &MainDebuggerWindow::onOpenExecutableClicked);
    connect(ui->btnAttachProcessContainer, &QAction::triggered, this, &MainDebuggerWindow::onAttachProcessClicked);
    connect(ui->btnDebugDynamicLibrary, &QAction::triggered, this, &MainDebuggerWindow::onDebugDynamicLibraryClicked);
    connect(ui->btnStopDebug, &QAction::triggered, this, &MainDebuggerWindow::onStopDebug);
    connect(ui->btnExit, &QAction::triggered, this, &MainDebuggerWindow::onExitClicked);

    /*
     * Block ListView Edit Value
     */
    ui->lstThreads->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->lstRegisters->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->lstStack->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->lstModules->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->lstUnloadedModules->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->lstCallStack->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->tblMemoryView->setEditTriggers( QAbstractItemView::NoEditTriggers );

    /*
     * Memory View Selection policy
     */
    ui->tblMemoryView->setSelectionMode(QAbstractItemView::SingleSelection); //Disable for allow user select multiples memory locations by time
    ui->tblMemoryView->setSelectionBehavior(QAbstractItemView::SelectRows);

    
}

void MainDebuggerWindow::onOpenExecutableClicked() {

    auto filePath = QFileDialog::getOpenFileName(this, "Open File", "", "Executable Files (*.exe);;All Files (*)");

    if (filePath.isEmpty()) {

        ui->statusbar->showMessage("[No Executable Selected]: Please, select a \".exe\" to continue.", 1000);

        return;
    }

    DebuggerEngine::GuiConfig guiCfg{ ui->lstRegisters, ui->lstStack, ui->statusbar, ui->lstThreads, ui->lstModules, ui->lstUnloadedModules, ui->lstCallStack, ui->tblMemoryView };

    this->m_dbgEngine = new DebuggerEngine(filePath.toStdWString(), guiCfg);

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

    //this->m_dbgEngine = new DebuggerEngine(process);

    qDebug() << "TODO";

}

void MainDebuggerWindow::onStopDebug() {

    this->m_dbgEngine->stopEngine();

}

MainDebuggerWindow::~MainDebuggerWindow()
{
    delete ui;
}
