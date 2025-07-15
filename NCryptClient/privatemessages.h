#ifndef PRIVATEMESSAGES_H
#define PRIVATEMESSAGES_H

#include "ConnectionManager.h"

#include <QAESEncryption.h>
#include <QWidget>

namespace Ui {
class PrivateMessages;
}

class PrivateMessages : public QWidget
{
    Q_OBJECT

public:
    explicit PrivateMessages(QWidget *parent, const QString &recipientNickname, const QByteArray &uuid,
                             const QByteArray &key, QAESEncryption::Aes keySize, QAESEncryption::Mode keyMode);
    ~PrivateMessages();
    QByteArray uuid() { return m_uuid; }
public slots:
    void onMessageDecrypted(const Message &message, const QByteArray &uuid);
    void onMessageSent();
    void onConversationDelete();
signals:
    void messageSent(const QByteArray &conversationUUID , const QString &message, qint64 timestamp);
    void conversationDeleted(const QByteArray &uuid);
private:
    Ui::PrivateMessages *ui;
    QByteArray m_uuid;


};

#endif // PRIVATEMESSAGES_H
