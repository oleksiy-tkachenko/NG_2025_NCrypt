#include "messagecard.h"
#include "mainwindow.h"
#include "ui_messagecard.h"

#include <QDateTime>

messageCard::messageCard(QWidget *parent, const QString &message, const QString &sender, qint64 timestamp)
    : QFrame(parent)
    , ui(new Ui::messageCard)
{
    ui->setupUi(this);
    ui->messageLabel->setText(message);
    ui->senderNicknameLabel->setText(sender);
    QString formattedTimestamp = QDateTime::fromSecsSinceEpoch(timestamp).toString("dd.MM.yyyy HH:mm");
    ui->timestamp->setText(formattedTimestamp);
    ui->senderProfilePicture->setPixmap(MainWindow::transformIntoProfilePicture(
                                        MainWindow::nicknamePictureMap[sender],
                                        ui->senderProfilePicture->height()));
}

messageCard::~messageCard()
{
    delete ui;
}
