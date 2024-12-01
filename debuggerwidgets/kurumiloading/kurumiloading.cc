/*
    File: KurumiLoading.cc
    Author: João Vitor(@Keowu)
    Created: 30/11/2024
    Last Update: 01/12/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#include "kurumiloading.hh"
#include "ui_kurumiloading.h"

KurumiLoading::KurumiLoading(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::KurumiLoading) {

    ui->setupUi(this);

    setFixedSize(size());
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);

}


KurumiLoading::~KurumiLoading() {

    delete ui;

}
