/*
    File: MainDebuggerWindow.cc
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 01/12/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "maindebuggerwindow.hh"
#include "./ui_maindebuggerwindow.h"
#include "debuggerwidgets/attachprocess/attachprocesswindow.hh"
#include "debuggerwidgets/custom/disasmview/harukadisasmhtmldelegate.hh"
#include "debuggerwidgets/patchs/memorypatchs.hh"
#include "debuggerwidgets/patchs/exportpatchs.hh"
#include "debuggerwidgets/patchs/importpatchs.hh"
#include "debuggerwidgets/processorfeatures/processorfeatures.hh"
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
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);
    setWindowFlags(Qt::MSWindowsFixedSizeDialogHint);

    /*
     * Slots
     */
    connect(ui->btnOpenExecutable, &QAction::triggered, this, &MainDebuggerWindow::onOpenExecutableClicked);
    connect(ui->btnAttachProcessContainer, &QAction::triggered, this, &MainDebuggerWindow::onAttachProcessClicked);
    connect(ui->btnRun, &QAction::triggered, this, &MainDebuggerWindow::onRunDebug);
    connect(ui->btnStepOver, &QAction::triggered, this, &MainDebuggerWindow::onStepOver);
    connect(ui->btnStepIn, &QAction::triggered, this, &MainDebuggerWindow::onStepIn);
    connect(ui->btnStepOut, &QAction::triggered, this, &MainDebuggerWindow::onStepOut);
    connect(ui->btnStop, &QAction::triggered, this, &MainDebuggerWindow::onStopDebug);
    connect(ui->btnAbout, &QAction::triggered, this, &MainDebuggerWindow::onAbout);
    connect(ui->btnExit, &QAction::triggered, this, &MainDebuggerWindow::onExitClicked);
    connect(ui->btnSendCommand, &QPushButton::clicked, this, &MainDebuggerWindow::OnCommandSendClicked);
    connect(ui->btnClear, &QPushButton::clicked, this, &MainDebuggerWindow::OnCommandClearClicked);
    connect(ui->lstRegisters, &QListView::clicked, this, &MainDebuggerWindow::onRegisterClicked);
    connect(ui->tabWidget, &QTabWidget::currentChanged, this, &MainDebuggerWindow::onUserTabChangedClick);
    connect(ui->btnOpenPdb, &QPushButton::clicked, this, &MainDebuggerWindow::OnLoadPdbClicked);
    connect(ui->btnClearPdb, &QPushButton::clicked, this, &MainDebuggerWindow::OnClearPdbClicked);
    connect(ui->tblPdbFunctions, &QTableView::clicked, this, &MainDebuggerWindow::onPdbFunctionClicked);
    connect(ui->btnColorMode, &QAction::triggered, this, &MainDebuggerWindow::onThemeColorModeClicked);
    connect(ui->btnMemoryPatchs, &QAction::triggered, this, &MainDebuggerWindow::onMemoryPatchs);
    connect(ui->btnExportPatchs, &QAction::triggered, this, &MainDebuggerWindow::onExportPatchs);
    connect(ui->btnImportPatchs, &QAction::triggered, this, &MainDebuggerWindow::onImportPatchs);
    connect(ui->btnProcessorFeatures, &QAction::triggered, this, &MainDebuggerWindow::onProcessorFeatures);

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
    ui->lstRegisteredVehs->setEditTriggers( QAbstractItemView::NoEditTriggers );
    ui->tblPdbFunctions->setEditTriggers( QAbstractItemView::NoEditTriggers );

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
    ui->tblPdbFunctions->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tblPdbFunctions->setSelectionBehavior(QAbstractItemView::SelectRows);

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

    auto filePath = QFileDialog::getOpenFileName(this, "Open a Executable File", "", "Executable Files (*.exe);;All Files (*)");

    if (filePath.isEmpty()) {

        ui->statusbar->showMessage("[No Executable Selected]: Please, select a \".exe\" to continue.", 1000);

        return;
    }

    /*if (!Kurumi::IsArm64(filePath.toStdString())) {

        qDebug() << "MiIsArm64:: Return false! Not supported PE FILE.";

        return;
    }*/

    DebuggerEngine::GuiConfig guiCfg{
                                     ui->lstRegisters, ui->lstStack, ui->statusbar, ui->lstThreads,
                                     ui->lstModules, ui->lstUnloadedModules, ui->lstCallStack, ui->tblMemoryView,
                                     ui->tblHandles, ui->tblInterrupts, ui->tblDisasmVw,
                                     { ui->memoryInspectorOne, ui->memoryInspectorTwo, ui->memoryInspectorThree },
                                     ui->outCommandConsole, ui->lstRegisteredVehs, ui->lstProcessCallbacks,
                                     ui->tblPdbFunctions, ui->lblPdbInspectorMetrics, ui->txtDecompiler,
                                     ui->tabWidget
    };

    this->m_dbgEngine = new DebuggerEngine(filePath.toStdWString(), guiCfg);

    //________________________________________________________
    //Enable the command interface for the ursers
    //________________________________________________________
    this->ui->lnCommand->setEnabled(true);

    this->ui->outCommandConsole->setEnabled(true);

    this->ui->btnSendCommand->setEnabled(true);

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

    this->m_dbgEngine->stepInto();

}

void MainDebuggerWindow::onStopDebug() {

    this->m_dbgEngine->stopEngine();

    this->m_dbgEngine->m_debugCommand = DebuggerEngine::RUNNING;

    this->m_dbgEngine->m_debugRule = DebuggerEngine::CurrentDebuggerRule::NO_RULE;

    this->m_dbgEngine->~DebuggerEngine();

    delete this->m_dbgEngine;

}

auto MainDebuggerWindow::onUserTabChangedClick(int index) -> void {

    if (index == 8) { //VEH/Generic-Handlers selected

        if (this->m_dbgEngine->isKurumiLoaded() && !this->m_dbgEngine->isDebugSessionActive()) {

            //Cleaning the QListsViews
            auto model = qobject_cast<QStringListModel*>(ui->lstRegisteredVehs->model());
            auto model2 = qobject_cast<QStringListModel*>(ui->lstProcessCallbacks->model());

            if (model) model->removeRows(0, model->rowCount());

            if (model2) model2->removeRows(0, model2->rowCount());

            //Detecting and extracting VEH Handlers
            this->m_dbgEngine->extractLdrpVectorHandlerListInformation();

            //Detect if Nirvana Instrumentation Callback is enabled on process
            this->m_dbgEngine->extractNirvanaCallbackPresentOnDebugeeProcess();

            //Detect and bring all information about Ntdll Callbacks from delegate tables
            this->m_dbgEngine->extractNtDelegateTableCallbacks();

        }

        else
            qDebug() << "Kurumi not loaded :(";

    }

}

auto MainDebuggerWindow::onMemoryPatchs() -> void {

    auto memPatchs = new MemoryPatchs(this, this->m_dbgEngine->getDebugCodePatchs(), this->m_dbgEngine->getDebuggeHandle());

    memPatchs->show();

}

auto MainDebuggerWindow::onExportPatchs() -> void {

    auto exportPatchs = new ExportPatchs(this, this->m_dbgEngine->getDebugCodePatchs());

    exportPatchs->show();

}

auto MainDebuggerWindow::onImportPatchs() -> void {

    auto impPatchs = new ImportPatchs(this, this->m_dbgEngine->getNewPatchCallback());

    impPatchs->show();

}

auto MainDebuggerWindow::onProcessorFeatures() -> void {

    auto procFeatures = new ProcessorFeatures(this);

    procFeatures->show();

}

void MainDebuggerWindow::onAbout() {

    QMessageBox msgBox;

    msgBox.setWindowTitle("About HarukaMirai DBG");
    msgBox.setText("(C) Fluxuss Software Security, LLC - HarukaDBG\n\nThis Version is Licensed to: João Vitor(@Keowu)\n\nVersion: DEV");
    msgBox.setIcon(QMessageBox::Information);
    msgBox.setStandardButtons(QMessageBox::Ok);

    msgBox.exec();

}

auto MainDebuggerWindow::OnCommandSendClicked() -> void {

    if (!this->ui->lnCommand->text().isEmpty()) {

        this->ui->outCommandConsole->append("We put the command: " + this->ui->lnCommand->text() + " for processing.");

        this->m_dbgEngine->m_commandProcessingQueue.push_back(new Lexer(this->ui->lnCommand->text()));

    }

    this->ui->lnCommand->clear();

}

auto MainDebuggerWindow::onRegisterClicked(const QModelIndex &index) -> void {

    if (!index.isValid()) return;

    auto model = this->ui->lstRegisters->model();

    this->ui->outCommandConsole->append(model->data(index).toString());

    //TODO MAKE BEATIFUL THE FLAGS FOR ARM64 AND X86_64 AND ALSO DISPLAY

}

void MainDebuggerWindow::onPdbFunctionClicked(const QModelIndex &index) {

    if (!index.isValid()) return;

    auto model = this->ui->tblPdbFunctions->model();

    QModelIndex address = model->index(index.row(), 1);
    QVariant value = model->data(address);

    qDebug() << "MainDebuggerWindow::onPdbFunctionClicked value:" << value.toString();

    bool ok{ FALSE };

    QString valueString = value.toString();

    if (valueString.startsWith("0x", Qt::CaseInsensitive)) {

        auto result = QStringView(valueString).mid(2).toULongLong(&ok, 16);

        if (ok) {

            this->m_dbgEngine->UpdateDisassemblerView(result);
            this->ui->tabWidget->setCurrentIndex(0);

        }

    }

}

auto MainDebuggerWindow::OnLoadPdbClicked() -> void {

    if (!this->m_dbgEngine || this->m_dbgEngine->isDebugSessionActive()) {

        qDebug() << "No Debug session started !";

        return;
    }

    auto filePath = QFileDialog::getOpenFileName(this, "Open a PDB File for the current debuggee program", "", "Program database (*.pdb);;All Files (*)");

    if (filePath.isEmpty()) {

        this->ui->statusbar->showMessage("[Error] Please select a valid PDB file.");

        return;
    }

    qDebug() << "MainDebuggerWindow::OnLoadPdbClicked";

    this->m_dbgEngine->extractPdbFileFunctions(filePath);

}

auto MainDebuggerWindow::OnClearPdbClicked() -> void {

    QStandardItemModel* pdbViewModel = qobject_cast<QStandardItemModel*>(ui->tblPdbFunctions->model());

    if (pdbViewModel) pdbViewModel->clear();
    else {

        pdbViewModel = new QStandardItemModel();
        ui->tblPdbFunctions->setModel(pdbViewModel);

    }

    ui->lblPdbInspectorMetrics->clear();

}

void MainDebuggerWindow::onThemeColorModeClicked() {

    qDebug() << "MainDebuggerWindow::onThemeColorModeClicked";

    if (!this->m_isDarkModeEnabled) {

        QFile f("themes\\dark.css");

        f.open(QFile::ReadOnly | QFile::Text);
        QTextStream ts(&f);
        setStyleSheet(ts.readAll());

        this->ui->btnColorMode->setText("Light Mode");

        this->m_isDarkModeEnabled = { TRUE };

    } else {

        this->ui->btnColorMode->setText("Dark Mode");

        setStyleSheet(NULL);

        this->m_isDarkModeEnabled = { FALSE };

    }
}

auto MainDebuggerWindow::OnCommandClearClicked() -> void {

    this->ui->outCommandConsole->clear();

}

MainDebuggerWindow::~MainDebuggerWindow()
{
    delete ui;
}
