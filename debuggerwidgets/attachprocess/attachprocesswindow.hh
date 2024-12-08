/*
    File: AttachProcessWindow.hh
    Authors: João Vitor(@Keowu)
    Created: 21/07/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. https://github.com/maldeclabs/koidbg. All rights reserved.
*/
#ifndef ATTACHPROCESSWINDOW_H
#define ATTACHPROCESSWINDOW_H

#include <QWidget>
#include <QStringListModel>
#include <windows.h>
#include <wtsapi32.h>

namespace Ui {
class AttachProcessWindow;
}

class AttachProcessWindow : public QWidget
{
    Q_OBJECT

public:
    explicit AttachProcessWindow(QWidget *parent = nullptr);
    auto GetRunningProcessList() -> void;
    auto onListViewClicked(const QModelIndex& index) -> void;
    ~AttachProcessWindow();

signals:
    void onProcessSelectedAttach(const std::pair<int, std::string>& process);

private:
    Ui::AttachProcessWindow *ui;
    std::vector<std::pair<uint32_t, std::string>> m_vecProcess;

};

#endif // ATTACHPROCESSWINDOW_H
