/*
    File: MainDebuggerWindow.cpp
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "maindebuggerwindow.h"
#include "./ui_maindebuggerwindow.h"
#include "debuggerwidgets/attachprocess/attachprocesswindow.h"
#include "debuggerwidgets/custom/disasmview/harukadisasmhtmldelegate.h"
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
    connect(ui->btnRun, &QAction::triggered, this, &MainDebuggerWindow::onRunDebug);
    connect(ui->btnStepOver, &QAction::triggered, this, &MainDebuggerWindow::onStepOver);
    connect(ui->btnStepIn, &QAction::triggered, this, &MainDebuggerWindow::onStepIn);
    connect(ui->btnStepOut, &QAction::triggered, this, &MainDebuggerWindow::onStepOut);
    connect(ui->btnStop, &QAction::triggered, this, &MainDebuggerWindow::onStopDebug);
    connect(ui->btnAbout, &QAction::triggered, this, &MainDebuggerWindow::onAbout);
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
    ui->tblHandles->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->tblDisasmVw->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->tblInterrupts->setEditTriggers( QAbstractItemView::NoEditTriggers );

    /*
     * Memory View/Handles Selection policy, and Vertical Header configuration
     */
    ui->tblMemoryView->setSelectionMode(QAbstractItemView::SingleSelection); //Disable for allow user select multiples memory locations by time
    ui->tblMemoryView->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tblHandles->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tblHandles->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tblDisasmVw->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tblDisasmVw->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tblInterrupts->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tblInterrupts->setSelectionBehavior(QAbstractItemView::SelectRows);

    ////////////////////////////////////////////////////////////
    /// We need to see if this shit will fuck with the code again
    ui->tblDisasmVw->verticalHeader()->setVisible(false);
    ////////////////////////////////////////////////////////////

    /*
     * Enabling Haruka Mirai Disassembler View HTML Delegate
     */
    HarukaDisasmHtmlDelegate *delegate = new HarukaDisasmHtmlDelegate(ui->tblDisasmVw);
    ui->tblDisasmVw->setItemDelegate(delegate);

    /*
     * Binding events for Debugger Widgets
     */
    connect(ui->tblInterrupts, &QTableView::clicked, this, &MainDebuggerWindow::OnInterruptListRowClicked);

}

void MainDebuggerWindow::onOpenExecutableClicked() {

    auto filePath = QFileDialog::getOpenFileName(this, "Open File", "", "Executable Files (*.exe);;All Files (*)");

    if (filePath.isEmpty()) {

        ui->statusbar->showMessage("[No Executable Selected]: Please, select a \".exe\" to continue.", 1000);

        return;
    }

    DebuggerEngine::GuiConfig guiCfg{ ui->lstRegisters, ui->lstStack, ui->statusbar, ui->lstThreads,
                                      ui->lstModules, ui->lstUnloadedModules, ui->lstCallStack, ui->tblMemoryView,
                                      ui->tblHandles, ui->tblInterrupts, ui->tblDisasmVw,
                                     { ui->memoryInspectorOne, ui->memoryInspectorTwo, ui->memoryInspectorThree }
    };

    this->m_dbgEngine = new DebuggerEngine(filePath.toStdWString(), guiCfg);

}

void MainDebuggerWindow::onAttachProcessClicked() {

    //test--------------------------------MOVE POINTER OFFSET ON HEXVIEW....
    //ui->memoryInspectorOne->ScrollToByFileOffset(0x3DF0);
    //TEST-------------------------------------------------------

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

auto MainDebuggerWindow::OnInterruptListRowClicked(const QModelIndex &index) -> void {

    qDebug() << "MainDebuggerWindow::OnInterruptListRowClicked";

    if (index.isValid()) {

        int row = index.row();

        auto debug = this->m_dbgEngine->getBreakpointByIndex(row);

        qDebug() << "Row clicked:" << QString::number(debug->m_ptrBreakpointAddress, 16);

        this->m_dbgEngine->RemoveInterrupting(debug);

        //Removing breakpoint from model of Tblinterrupts
        QStandardItemModel *model = qobject_cast<QStandardItemModel *>(ui->tblInterrupts->model());

        if (model) {

            if (row >= 0 && row < model->rowCount()) {

                model->removeRow(row);

            } else {

                qWarning("Row index is out of range.");

            }
        } else {

            qWarning("Model is not of type QStandardItemModel.");

        }

        //Removing breakpoint item instance from DebugBreakPoint vector list
        this->m_dbgEngine->removeBreakpointItemByIndex(row);

    }

}

void MainDebuggerWindow::onRunDebug() {

    this->m_dbgEngine->m_debugCommand = DebuggerEngine::RUNNING;

}

void MainDebuggerWindow::onStepOver() {

    this->m_dbgEngine->stepOver();

}

void MainDebuggerWindow::onStepOut() {

    this->m_dbgEngine->stepOut();

}

void MainDebuggerWindow::onStepIn() {

    qDebug() << "MainDebuggerWindow::onStepIn";

}

void MainDebuggerWindow::onStopDebug() {

    this->m_dbgEngine->stopEngine();

    this->m_dbgEngine->m_debugCommand = DebuggerEngine::RUNNING;

    this->m_dbgEngine->m_debugRule = DebuggerEngine::CurrentDebuggerRule::NO_RULE;

    this->m_dbgEngine->~DebuggerEngine();

    delete this->m_dbgEngine;

}

void MainDebuggerWindow::onAbout() {

    QMessageBox msgBox;

    msgBox.setWindowTitle("About HarukaMirai DBG");
    msgBox.setText("(C) Fluxuss Software Security, LLC - HarukaDBG\n\nThis Version is Licensed to: João Vitor(@Keowu)\n\nModules for this license:\n- X86_64\n- ARM64\n\nVersion: 1.51.3");
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setStandardButtons(QMessageBox::Ok);

    msgBox.exec();

}

MainDebuggerWindow::~MainDebuggerWindow()
{
    delete ui;
}
