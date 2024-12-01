/*
    File: processorfeatures.cc
    Author: João Vitor(@Keowu)
    Created: 25/11/2024
    Last Update: 25/11/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "processorfeatures.hh"
#include "ui_processorfeatures.h"

ProcessorFeatures::ProcessorFeatures(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::ProcessorFeatures) {

    ui->setupUi(this);

    /*
     *  Disable MAXIMIZE Button and Disable FORM Resizing
    */
    setFixedSize(size());
    setWindowFlags(windowFlags() & ~Qt::WindowMaximizeButtonHint);


}


ProcessorFeatures::~ProcessorFeatures() {

    delete ui;

}
