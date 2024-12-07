/*
    File: processorfeatures.cc
    Author: João Vitor(@Keowu)
    Created: 25/11/2024
    Last Update: 06/12/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "processorfeatures.hh"
#include "ui_processorfeatures.h"

ProcessorFeatures::ProcessorFeatures(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::ProcessorFeatures) {

    ui->setupUi(this);

    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);

    this->ui->lblProcessorBasicInfo->setText(this->armProcInfo.get()->m_vendorName + " " + this->armProcInfo.get()->m_processorName + " " + this->armProcInfo.get()->m_Identifier);
    this->ui->lblProcessorFeatures->setText(this->armProcInfo.get()->m_processorFeatures);
    this->ui->lblProcessorCores->setText(this->armProcInfo.get()->m_distinctCores);
    this->ui->txtProcessoriIsaLevel->setPlainText(this->armProcInfo.get()->m_isaLevel);
    this->ui->txtProcessorIsaFeatures->setPlainText(this->armProcInfo.get()->m_isaFeatures);

}


ProcessorFeatures::~ProcessorFeatures() {

    delete ui;

}
