/*
    File: AttachProcessWindow.cpp
    Author: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 25/08/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "attachprocesswindow.h"
#include "ui_attachprocesswindow.h"

AttachProcessWindow::AttachProcessWindow(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::AttachProcessWindow)
{
    ui->setupUi( this );

    this->GetRunningProcessList( );

    connect(ui->listView, &QListView::clicked, this, &AttachProcessWindow::onListViewClicked);

}

auto AttachProcessWindow::onListViewClicked(const QModelIndex& index) -> void {

    auto selectedProcess = this->m_vecProcess.at( index.row() );

    qDebug() << "Name: " << selectedProcess.second << "\n";

    emit onProcessSelectedAttach(selectedProcess);

    this->close();

}

auto AttachProcessWindow::GetRunningProcessList( ) -> void {

    WTS_PROCESS_INFOA* pi;
    DWORD dwCount { 0 };

    auto listModel = new QStringListModel( this );

    ui->listView->setEditTriggers( QAbstractItemView::NoEditTriggers );

    ui->listView->setModel( listModel );

    if ( !WTSEnumerateProcessesA(
        
        WTS_CURRENT_SERVER_HANDLE,
        0,
        1,
        &pi,
        &dwCount
    
    ) ) return;

    for ( DWORD i = 0; i < dwCount; i++ ) {

        QString procInfo(QString::number(pi[i].ProcessId) + "      -       " + pi[i].pProcessName);

        auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pi[i].ProcessId);

        procInfo += "      -       ";

        if (hProcess != INVALID_HANDLE_VALUE) {

            USHORT uProcessMachine{ 0 }, uProcessHostMachine{ 0 };
            
            IsWow64Process2(hProcess, &uProcessMachine, &uProcessHostMachine);

            switch (uProcessMachine)
            {
            case IMAGE_FILE_MACHINE_ARM64:
                procInfo += "ARM64 architecture.";
                break;
            case IMAGE_FILE_MACHINE_AMD64:
                procInfo += "x64 (AMD64) architecture.";
                break;
            case IMAGE_FILE_MACHINE_I386:
                procInfo += "x86 (32-bit) architecture.";
                break;
            default:
                procInfo += "Unknown architecture.";
                break;
            }

        }
        else {

            procInfo += "Unknown architecture(No Permission).";

        }

        CloseHandle(hProcess);

        this->m_vecProcess.push_back( {

            pi[i].ProcessId,
            pi[i].pProcessName

        } );

        auto lines = listModel->stringList( );

        lines.append( procInfo );

        listModel->setStringList( lines );
    }

    WTSFreeMemory(
        
        pi
    
    );

    return;
}

AttachProcessWindow::~AttachProcessWindow() {

    this->m_vecProcess.clear();

    delete ui;
}
