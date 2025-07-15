#include "privatemessages.h"
#include "connectionmanager.h"
#include "mainwindow.h"
#include "ui_privatemessages.h"
#include <QJsonObject>
#include <messageCard.h>
#include <QDateTime>
#include <QMessageBox>

PrivateMessages::PrivateMessages(QWidget *parent, const QString &recipientNickname, const QByteArray &uuid,
                             const QByteArray &key, QAESEncryption::Aes keySize, QAESEncryption::Mode keyMode)
    : QWidget(parent)
    , ui(new Ui::PrivateMessages)
{
    m_uuid = uuid;
    ui->setupUi(this);
    ui->recipientProfilePicutreLabel->setPixmap(MainWindow::transformIntoProfilePicture(
                                                MainWindow::nicknamePictureMap[recipientNickname],
                                                ui->recipientProfilePicutreLabel->height()));
    ui->recipientNicknameLabel->setText(recipientNickname);
    EncryptionType encryptionType = ConnectionManager::instance()->getCurrentEncryptionType();
    if(encryptionType == EncryptionType::AESRSA){
        QString mode;
        switch (keyMode){
        case QAESEncryption::ECB:
            mode = "!!!ECB!!!";
            break;
        case QAESEncryption::CBC:
            mode = "CBC";
            break;
        case QAESEncryption::OFB:
            mode = "OFB";
            break;
        case QAESEncryption::CFB:
            mode = "CFB";
            break;
        }

        ui->conversationInfo->setText("This conversation uses AES+RSA encryption, with AES key size " + QString::number(8*(2+(int)keySize)) + " and AES mode " + mode);
    } else {
        ui->conversationInfo->setText("This conversation uses !!!only RSA!!! encryption, with RSA key size 2048");
    }

    ConnectionManager::instance()->setCurrentAESSize(keySize);
    ConnectionManager::instance()->setCurrentAESMode(keyMode);
    ConnectionManager::instance()->setCurrentKey(key);
    ConnectionManager::instance()->setConversationUUID(m_uuid);
    ConnectionManager::instance()->setCurrentDestinationType(false);
    ui->messagesContainerLayout->setAlignment(Qt::AlignTop);
    connect(ui->sendMessageBtn, &QAbstractButton::pressed, this, &PrivateMessages::onMessageSent);
    connect(ConnectionManager::instance(), &ConnectionManager::messageDecrypted, this, &PrivateMessages::onMessageDecrypted);
    connect(this, &PrivateMessages::messageSent, (MainWindow*)parent, &MainWindow::onMessageSent);
    connect(ui->backToDefaultBtn, &QAbstractButton::pressed, (MainWindow*)parent, &MainWindow::setDefaultWidget);
    connect(ui->deleteConversationBtn, &QAbstractButton::pressed, this, &PrivateMessages::onConversationDelete);
    ConnectionManager::instance()->getMessages(m_uuid);
}

PrivateMessages::~PrivateMessages()
{
    delete ui;
}

void PrivateMessages::onMessageDecrypted(const Message &message, const QByteArray &uuid)
{
    if(m_uuid == uuid){
        ui->messagesContainerLayout->addWidget(new messageCard(this, message.message, message.sender, message.timestamp));
    }
}

void PrivateMessages::onMessageSent()
{
    QString message = ui->messageTE->toPlainText().trimmed();
    ui->messageTE->clear();
    if(!ConnectionManager::instance()->sendMessage(message)) return;
    QString sender = ConnectionManager::instance()->nickname();
    qint64 timestamp = QDateTime::currentSecsSinceEpoch();
    ui->messagesContainerLayout->addWidget(new messageCard(this, message, sender, timestamp));
    emit messageSent(m_uuid, message, timestamp);
}

void PrivateMessages::onConversationDelete()
{
    QMessageBox::StandardButton reply =
        QMessageBox::question(this,
            "Delete Conversation",
            "Are you sure you want to delete this conversation?",
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
    if(reply == QMessageBox::Yes){
        emit conversationDeleted(m_uuid);
    }
}
