#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <ConnectionManager.h>
#include <RegistrationDialog.h>
#include <QJsonObject>
#include <QPainter>
#include <QPainterPath>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    ui->setupUi(this);

    connect(ConnectionManager::instance(), &ConnectionManager::dataReceived, this, &MainWindow::onDataRecieved);

    ui->nickname->setText(ConnectionManager::instance()->nickname());
    ConnectionManager::instance()->getPictureData();
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onDataRecieved(const QJsonObject &response)
{
    qDebug() << "got data";
    if(response["response_type"].toString() == "picture"){
        qDebug() << "trying to set picture";
        setPicture(response);
    }
}

QPixmap MainWindow::transformPicture(const QPixmap &source, int size){
    QPixmap result(size, size);
    result.fill(Qt::transparent);
    QPainter painter(&result);
    painter.setRenderHint(QPainter::Antialiasing);
    QPainterPath path;
    path.addEllipse(0, 0, size, size);
    painter.setClipPath(path);
    painter.drawPixmap(0, 0, source.scaled(size, size, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation));

    return result;
}

void MainWindow::setPicture(const QJsonObject &response)
{
    QPixmap picture;
    qDebug() << "The picture: " << response["picture"].toString();
    if(response["picture"].isNull() || response["picture"].toString().isEmpty()){
        picture.load(":/ncrypt.png");
    } else {
        QByteArray pictureData = QByteArray::fromBase64(response["picture"].toString().toUtf8());
        picture.loadFromData(pictureData);
    }
    picture = transformPicture(picture, ui->profilePictureBtn->height());
    if(!response.contains("nickname")){
        ui->profilePictureBtn->setIconSize(ui->profilePictureBtn->size());
        ui->profilePictureBtn->setIcon(QIcon(picture));
    }
}
