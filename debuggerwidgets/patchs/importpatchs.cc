/*
    File: importpatchs.cc
    Author: João Vitor(@Keowu)
    Created: 17/11/2024
    Last Update: 17/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "importpatchs.hh""
#include "ui_importpatchs.h"

ImportPatchs::ImportPatchs(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::ImportPatchs)
{
    ui->setupUi(this);

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
    */
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);
    //setWindowFlags(Qt::MSWindowsFixedSizeDialogHint);

}

ImportPatchs::~ImportPatchs()
{
    delete ui;
}
