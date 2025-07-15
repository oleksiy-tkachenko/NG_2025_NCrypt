#include "conversationcard.h"
#include "mainwindow.h"
#include "ui_conversationcard.h"
#include <QMouseEvent>

ConversationCard::ConversationCard(QWidget *parent, const QString &recipientNickname, const QByteArray &key,
                                   const QByteArray &uuid, QAESEncryption::Aes keySize, QAESEncryption::Mode keyMode, int encryptionType,
                                   const QString &lastMessage, const QString &lastMessageSender, qint64 lastMessageTime)
    : QFrame(parent)
    , ui(new Ui::ConversationCard)
{
    ui->setupUi(this);
    ui->recipientNickname->setText(recipientNickname);
    m_lastMessage = lastMessage;
    m_lastMessageTime = lastMessageTime;
    m_lastMessageSender = lastMessageSender;
    if(!lastMessage.isEmpty()){
        setNewLastMessageInfo(lastMessage, lastMessageSender, lastMessageTime);
    } else {
        m_lastMessageTime = QDateTime::currentSecsSinceEpoch();
    }
    m_recipientNickname = recipientNickname;
    m_uuid = uuid;
    m_key = key;
    m_keySize = keySize;
    m_keyMode = keyMode;
    m_encryptionType = EncryptionType(encryptionType);
    MainWindow *mainWindow = (MainWindow*)parent;
    connect(mainWindow, &MainWindow::pictureReady, this, &ConversationCard::onPictureReady);
}

ConversationCard::~ConversationCard()
{
    delete ui;
}

void ConversationCard::onPictureReady(const QString &nickname)
{
    if (nickname == m_recipientNickname){
        ui->recipientProfilePicture->setPixmap(MainWindow::transformIntoProfilePicture(MainWindow::nicknamePictureMap[nickname],
                                                                                       ui->recipientProfilePicture->height()));
    }
}

void ConversationCard::setNewLastMessageInfo(const QString &lastMessage,
                                             const QString &lastMessageSender,
                                             qint64 lastMessageTime){
    QString lastMessageInfo = lastMessageSender + ": " + lastMessage;
    if(lastMessageInfo == ": ") return;
    QFontMetrics fm(ui->lastMessageInfo->font());
    QString elided = fm.elidedText(lastMessageInfo, Qt::ElideRight, ui->lastMessageInfo->width());
    ui->lastMessageInfo->setText(elided);
    QString lastMessageTimeFormatted = QDateTime::fromSecsSinceEpoch(lastMessageTime).toString("HH:mm");
    ui->lastMessageTime->setText(lastMessageTimeFormatted);
}

void ConversationCard::resizeEvent(QResizeEvent *ev) {
    QFrame::resizeEvent(ev);
    QString lastMessageInfo = m_lastMessageSender + ": "+m_lastMessage;
    if (lastMessageInfo == ": ") return;
    QFontMetrics fm(ui->lastMessageInfo->font());
    int w = ui->lastMessageInfo->width();
    ui->lastMessageInfo->setText(fm.elidedText(lastMessageInfo, Qt::ElideRight, w));
}

void ConversationCard::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) {
        emit pressed(m_recipientNickname, m_uuid, m_key, m_keySize, m_keyMode, m_encryptionType);
    }
}
