#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QSqlDatabase>

struct ConversationInfo {
    QString   nickname;
    QByteArray key;
    QByteArray uuid;
    QByteArray lastMessage;
    qint64 lastMessageTime;
    int encryptionType;
    QString   lastMessageSender;
    int keySize;
    int keyMode;
};

struct Message{
    QByteArray message;
    QString sender;
    qint64 timestamp;
};

class DatabaseManager
{
public:
    DatabaseManager(const QString& path);
    bool userExists(const QString &nickname);
    bool addUser(const QString &nickname, const QByteArray &salt, const QByteArray &publicKey, const QByteArray &privateKey);
    QByteArray getUserValue(const QString &nickname, const QString &valueName);
    QVector<ConversationInfo> getConversations(const QString &senderNickname, bool fetchNew = false, qint64 lastUpdateTime = 0);
    QVector<Message> getMessages(const QByteArray &uuid);
    bool updatePicture(QByteArray &pictureData, const QString &nickname);
    bool conversationExists(const QByteArray &uuid);
    bool conversationExists(const QString &senderNickname, const QString &recipientNickname);
    bool createConversation(const QString &senderNickname, const QString &recipientNickname, const QByteArray &uuid);
    bool senderPresent(const QString &senderNickname, const QByteArray &uuid);
    bool finalizeConversation(const QByteArray &senderKey, const QByteArray &recipientKey, int keySize,
                              int keyMode, int encryptionType, const QByteArray &uuid);
    void deleteConversation(const QByteArray &uuid);
    void addLastMessageToConversation(const QByteArray &uuid, const QByteArray &message,
                                      const QString &sender, qint64 timestamp);
    bool addMessage(const QByteArray &message, const QString &sender, qint64 timestamp, const QByteArray &uuid, bool uuidType);
    bool channelExists(const QByteArray &uuid);
    QString getRecipientNickname(const QString &sender, const QByteArray &conversation_uuid);

private:
    QSqlDatabase m_database;

    QSqlQuery getAllConversationsQuery(const QString &senderNickname);
    QSqlQuery getNewConversationsQuery(const QString &senderNickname, qint64 lastUpdateTime);
};

#endif // DATABASEMANAGER_H
