/*
    File: memorypatchs.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 24/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "memorypatchs.hh"
#include "ui_memorypatchs.h"

MemoryPatchs::MemoryPatchs(QWidget *parent, std::vector<DebugCodePatchs>* codePatchs, HANDLE hProcess)
    : QMainWindow(parent)
    , ui(new Ui::MemoryPatchs), m_codePatchs(codePatchs), m_hProcess(hProcess) {

    ui->setupUi(this);

    ui->lstAppliedPatchs->setEditTriggers( QAbstractItemView::NoEditTriggers );

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
    */
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);

    connect(ui->lstAppliedPatchs, &QListView::clicked, this, &MemoryPatchs::onAppliedPatchListClicked);

    /*
     * Preparing the list view with actual patchs
     */
    this->updateMemoryPatchsList();

}

auto MemoryPatchs::updateMemoryPatchsList() -> void {

    QStringList qStringPatchs;
    for (const auto &patch : *this->m_codePatchs) qStringPatchs.append(QString("%1!0x%2")
                                 .arg(patch.m_module.m_qStName)
                                 .arg(patch.m_patchOffset, 0, 16));

    auto model = new QStringListModel();
    model->setStringList(qStringPatchs);

    this->ui->lstAppliedPatchs->setModel(model);

}

auto MemoryPatchs::onAppliedPatchListClicked(const QModelIndex &index) -> void {

    if (!index.isValid() && index.row() < this->m_codePatchs->size()) return;

    auto patch = this->m_codePatchs->at(index.row());

    if (this->m_hProcess == INVALID_HANDLE_VALUE) return;

    ::WriteProcessMemory(

        this->m_hProcess,
        reinterpret_cast<PVOID>(patch.m_module.m_lpModuleBase + patch.m_patchOffset),
        patch.m_originalCode.data(),
        patch.m_originalCode.size(),
        NULL

    );

    this->m_codePatchs->erase(this->m_codePatchs->begin() + index.row());

    /*
     * Updating the list view with actual patchs
     */
    this->updateMemoryPatchsList();

}

MemoryPatchs::~MemoryPatchs() {

    delete ui;

}
