/*
    File: KurumiLoading.hh
    Authors: João Vitor(@Keowu)
    Created: 30/11/2024
    Last Update: 01/12/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef KURUMILOADING_HH
#define KURUMILOADING_HH

#include <QMainWindow>

namespace Ui {
    class KurumiLoading;
}

class KurumiLoading : public QMainWindow {

    Q_OBJECT

public:
    explicit KurumiLoading(QWidget *parent = nullptr);
    ~KurumiLoading();

private:
    Ui::KurumiLoading *ui;

};

#endif // KURUMILOADING_HH
