/*
    File: harukadisasmhtmldelegate.h
    Author: João Vitor(@Keowu)
    Created: 24/08/2024
    Last Update: 08/09/2024

    Copyright (c) 2024. github.com/keowu/harukamiraidbg. All rights reserved.
*/
#ifndef HARUKADISASMHTMLDELEGATE_H
#define HARUKADISASMHTMLDELEGATE_H
#include <QStyledItemDelegate>
#include <QTextDocument>
#include <QPainter>

class HarukaDisasmHtmlDelegate : public QStyledItemDelegate {
public:
    HarukaDisasmHtmlDelegate(QObject *parent = nullptr) : QStyledItemDelegate(parent) {}

    void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override {
        QString htmlText = index.data(Qt::DisplayRole).toString();
        QTextDocument doc;
        doc.setHtml(htmlText);
        doc.setTextWidth(option.rect.width());
        QSize docSize = doc.size().toSize();
        if (docSize.height() > option.rect.height()) {
            docSize.setHeight(option.rect.height());
        }

        painter->save();
        painter->setClipRect(option.rect);
        painter->translate(option.rect.topLeft());
        doc.drawContents(painter);
        painter->restore();
    }
};

#endif // HARUKADISASMHTMLDELEGATE_H
