/*
    File: exportpatchs.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "exportpatchs.hh"
#include "ui_exportpatchs.h"

ExportPatchs::ExportPatchs(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::ExportPatchs)
{
    ui->setupUi(this);

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
    */
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);
    //setWindowFlags(Qt::MSWindowsFixedSizeDialogHint);

}

ExportPatchs::~ExportPatchs()
{
    delete ui;
}
