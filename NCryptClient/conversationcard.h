#ifndef CONVERSATIONCARD_H
#define CONVERSATIONCARD_H

#include "connectionmanager.h"
#include <QAESEncryption.h>
#include <QFrame>

namespace Ui {
class ConversationCard;
}

class ConversationCard : public QFrame
{
    Q_OBJECT

public:
    explicit ConversationCard(QWidget *parent, const QString &recipientNickname,
                              const QByteArray &key, const QByteArray &uuid,
                              QAESEncryption::Aes keySize, QAESEncryption::Mode keyMode,  int encryptionType,
                              const QString &lastMessage, const QString &lastMessageSender,
                              qint64 lastMessageTime);
    ~ConversationCard();
    QString recipientNickname(){ return m_recipientNickname; }
    QByteArray uuid(){ return m_uuid; }
    QByteArray key(){ return m_key; }
    qint64 lastMessageTime(){ return m_lastMessageTime; }
    QAESEncryption::Aes keySize(){ return m_keySize; }
    QAESEncryption::Mode keyMode(){ return m_keyMode; }
    void setNewLastMessageInfo(const QString &lastMessage, const QString &lastMessageSender, qint64 lastMessageTime);
    void resizeEvent(QResizeEvent *ev) override;
public slots:
    void onPictureReady(const QString &nickname);
signals:
    void pressed(const QString &recipientNickname, const QByteArray &uuid,
                 const QByteArray &key, QAESEncryption::Aes keySize,
                 QAESEncryption::Mode keyMode, EncryptionType encryptionType);
private:
    QString m_lastMessage;
    QString m_lastMessageSender;
    QString m_recipientNickname;
    QByteArray m_uuid;
    QByteArray m_key;
    qint64 m_lastMessageTime;
    QAESEncryption::Aes m_keySize;
    QAESEncryption::Mode m_keyMode;
    Ui::ConversationCard *ui;
    void mousePressEvent(QMouseEvent *event) override;
    EncryptionType m_encryptionType;

};

#endif // CONVERSATIONCARD_H
