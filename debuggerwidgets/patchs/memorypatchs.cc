/*
    File: memorypatchs.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "memorypatchs.hh"
#include "ui_memorypatchs.h"

MemoryPatchs::MemoryPatchs(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MemoryPatchs)
{
    ui->setupUi(this);

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
    */
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);
    //setWindowFlags(Qt::MSWindowsFixedSizeDialogHint);

}

MemoryPatchs::~MemoryPatchs()
{
    delete ui;
}
