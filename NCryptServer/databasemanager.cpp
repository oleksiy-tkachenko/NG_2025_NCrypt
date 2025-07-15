#include "databasemanager.h"
#include <QDebug>
#include <QSqlQuery>
#include <QSqlError>
#include <QBuffer>
#include <QImageReader>

DatabaseManager::DatabaseManager(const QString& path) {
    m_database = QSqlDatabase::addDatabase("QSQLITE");
    m_database.setDatabaseName(path);

    if (!m_database.open())
    {
        qDebug() << "Error: connection with database failed";
    }
    else
    {
        qDebug() << "Database: connection ok";
    }
    QSqlQuery query;
    QString createUsersTable =
        "CREATE TABLE IF NOT EXISTS users ("
        "nickname TEXT PRIMARY KEY,"
        "salt BLOB,"
        "private_key BLOB,"
        "public_key BLOB,"
        "picture BLOB);";
    if (!query.exec(createUsersTable)) {
        qDebug() << "Create table failed:" << query.lastError();
    }
    QString createConversationsTable =
        "CREATE TABLE IF NOT EXISTS conversations ("
        "conversation_uuid BLOB PRIMARY KEY, "
        "sender_nickname TEXT, "
        "recipient_nickname TEXT, "
        "sender_key BLOB, "
        "recipient_key BLOB, "
        "key_size INTEGER, "
        "key_mode INTEGER, "
        "encryption_type INTEGER, "
        "last_message BLOB, "
        "last_message_time INTEGER, "
        "last_message_sender TEXT);";
    if (!query.exec(createConversationsTable)) {
        qDebug() << "Create table failed:" << query.lastError();
    }
    QString createMessagesTable =
  "CREATE TABLE IF NOT EXISTS messages ("
  "message_id INTEGER PRIMARY KEY AUTOINCREMENT, "
  "conversation_uuid BLOB, "
  "channel_uuid BLOB, "
  "sender_nickname TEXT NOT NULL, "
  "timestamp INTEGER NOT NULL, "
  "message BLOB NOT NULL, "
  "FOREIGN KEY(conversation_uuid)"
    "REFERENCES conversations(conversation_uuid)"
    "ON DELETE CASCADE);";
    if (!query.exec(createMessagesTable)){
        qDebug() << "Create table failed:" << query.lastError();
    }
}

bool DatabaseManager::addUser(const QString& nickname, const QByteArray &salt, const QByteArray &publicKey, const QByteArray &privateKey)
{
    bool success = false;
    QSqlQuery query;
    query.prepare("INSERT INTO users (nickname, salt, private_key, public_key) "
                         "VALUES (:nickname, :salt, :private_key, :public_key)");
    query.bindValue(":nickname", nickname);
    query.bindValue(":salt", salt);
    query.bindValue(":private_key", privateKey);
    query.bindValue(":public_key", publicKey);

    if(query.exec())
    {
        success = true;
    }
    else
    {
        qDebug() << "addUser error:"
                 << query.lastError();
    }

    return success;
}



bool DatabaseManager::userExists(const QString &nickname){
    QSqlQuery query;
    query.prepare("SELECT 1 FROM users WHERE nickname = :nickname LIMIT 1");
    query.bindValue(":nickname", nickname);

    if (query.exec())
    {
        return query.next();
    }
    return false;
}

QByteArray DatabaseManager::getUserValue(const QString &nickname, const QString &valueName){
    QSqlQuery query;
    query.prepare(QString("SELECT %1 FROM users WHERE nickname = :nickname").arg(valueName));
    query.bindValue(":nickname", nickname);

    if (query.exec()) {
        if(query.next()){
            return query.value(0).toByteArray();
        }
    }
    qDebug() << "Query execution failed:" << query.lastError();
    return QByteArray();
}

QVector<ConversationInfo> DatabaseManager::getConversations(const QString &senderNickname, bool fetchNew, qint64 lastUpdateTime)
{
    QSqlQuery query;
    if(fetchNew){
        query = getNewConversationsQuery(senderNickname, lastUpdateTime);
    } else {
        query = getAllConversationsQuery(senderNickname);
    }
    if (!query.exec()) {
        qDebug() << "Failed to load conversations:" << query.lastError().text();
        return QVector<ConversationInfo>();
    }
    QVector<ConversationInfo> list;
    while (query.next()) {
        ConversationInfo info;
        info.nickname = query.value("nickname").toString();
        info.key = query.value("key").toByteArray();
        info.uuid = query.value("conversation_uuid").toByteArray();
        info.keyMode = query.value("key_mode").toInt();
        info.keySize = query.value("key_size").toInt();
        info.encryptionType = query.value("encryption_type").toInt();
        info.lastMessage = query.value("last_message").toByteArray();
        info.lastMessageTime = query.value("last_message_time").toLongLong();
        info.lastMessageSender = query.value("last_message_sender").toString();
        list.append(info);
    }
    return list;
}

QSqlQuery DatabaseManager::getAllConversationsQuery(const QString &senderNickname)
{
    QSqlQuery query;
    query.prepare("SELECT CASE WHEN sender_nickname = :sender THEN recipient_nickname ELSE sender_nickname END AS nickname, "
                  "CASE WHEN sender_nickname = :sender THEN sender_key ELSE recipient_key END AS key, "
                  "conversation_uuid, "
                  "encryption_type, "
                  "key_mode, "
                  "key_size, "
                  "last_message, "
                  "last_message_time, "
                  "last_message_sender "
                  "FROM conversations WHERE :sender IN (sender_nickname, recipient_nickname)");
    query.bindValue(":sender", senderNickname);
    return query;
}

QSqlQuery DatabaseManager::getNewConversationsQuery(const QString &senderNickname, qint64 lastUpdateTime)
{
    QSqlQuery query;
    query.prepare("SELECT CASE WHEN sender_nickname = :sender THEN recipient_nickname ELSE sender_nickname END AS nickname, "
                  "CASE WHEN sender_nickname = :sender THEN sender_key ELSE recipient_key END AS key, "
                  "conversation_uuid, "
                  "encryption_type, "
                  "key_mode, "
                  "key_size, "
                  "last_message, "
                  "last_message_time, "
                  "last_message_sender "
                  "FROM conversations WHERE :sender IN (sender_nickname, recipient_nickname) "
                  "AND last_message_time > :update");
    query.bindValue(":sender", senderNickname);
    query.bindValue(":update", lastUpdateTime);
    return query;
}

QVector<Message> DatabaseManager::getMessages(const QByteArray &uuid)
{
    QSqlQuery query;
    query.prepare("SELECT message, sender_nickname, timestamp "
                  "FROM messages WHERE conversation_uuid = :uuid");
    query.bindValue(":uuid", uuid);
    if (!query.exec()) {
        qDebug() << "Failed to load conversations:" << query.lastError().text();
        return QVector<Message>();
    }
    QVector<Message> messages;
    while (query.next()) {
        Message message;
        message.message = query.value("message").toByteArray();
        message.sender = query.value("sender_nickname").toString();
        message.timestamp = query.value("timestamp").toLongLong();
        messages.append(message);
    }
    return messages;
}

bool DatabaseManager::updatePicture(QByteArray &pictureData, const QString &nickname)
{
    QBuffer buffer(&pictureData);
    buffer.open(QIODevice::ReadOnly);

    QImageReader reader(&buffer);

    if (!reader.canRead()) {
        return false;
    }
    QString imgFormat = reader.format().toLower();
    QImage img = reader.read();
    if (img.isNull() || img.width() != 100 || img.height() != 100 ||
        (imgFormat != "jpeg" && imgFormat != "jpg")) {
        return false;
    }
    QSqlQuery query;
    query.prepare("UPDATE users SET picture = :picture WHERE nickname = :nickname");
    query.bindValue(":picture", pictureData);
    query.bindValue(":nickname", nickname);

    if (!query.exec()) {
        qDebug() << "Failed to update profile picture:" << query.lastError();
        return false;
    }
    return true;
}

bool DatabaseManager::conversationExists(const QByteArray &uuid)
{
    QSqlQuery query;
    query.prepare("SELECT 1 FROM conversations WHERE conversation_uuid = :uuid LIMIT 1");
    query.bindValue(":uuid", uuid);

    if (query.exec())
    {
        return query.next();
    }
    return false;
}

bool DatabaseManager::conversationExists(const QString &senderNickname, const QString &recipientNickname)
{
    QSqlQuery query;
    query.prepare("SELECT 1 FROM conversations WHERE (sender_nickname   = :sn AND recipient_nickname = :rn) "
        "OR (sender_nickname   = :rn AND recipient_nickname = :sn) LIMIT 1");
    query.bindValue(":sn", senderNickname);
    query.bindValue(":rn", recipientNickname);

    if (query.exec())
    {
        return query.next();
    }
    return false;
}

bool DatabaseManager::createConversation(const QString &senderNickname, const QString &recipientNickname, const QByteArray &uuid)
{
    bool success = false;
    QSqlQuery query;
    query.prepare("INSERT INTO conversations (sender_nickname, recipient_nickname, conversation_uuid) "
                  "VALUES (:sn, :rn, :uuid)");
    query.bindValue(":sn", senderNickname);
    query.bindValue(":rn", recipientNickname);
    query.bindValue(":uuid", uuid);

    if(query.exec())
    {
        success = true;
    }
    else
    {
        qDebug() << "createConversation error:"
                 << query.lastError();
    }

    return success;
}

bool DatabaseManager::senderPresent(const QString &senderNickname, const QByteArray &uuid)
{
    QSqlQuery query;
    query.prepare("SELECT 1 FROM conversations WHERE (sender_nickname   = :sn "
                  "OR recipient_nickname = :sn) AND conversation_uuid = :uuid LIMIT 1");
    query.bindValue(":sn", senderNickname);
    query.bindValue(":uuid", uuid);
    if (query.exec())
    {
        return query.next();
    }
    return false;
}

bool DatabaseManager::finalizeConversation(const QByteArray &senderKey, const QByteArray &recipientKey, int keySize,
                                           int keyMode, int encryptionType, const QByteArray &uuid)
{
    QSqlQuery query;
    query.prepare("UPDATE conversations SET sender_key = :sk, recipient_key = :rk, key_size = :ksize,"
                  " key_mode = :kmode, encryption_type = :etype, last_message_time = :time WHERE conversation_uuid = :uuid");
    query.bindValue(":sk", senderKey);
    query.bindValue(":rk", recipientKey);
    query.bindValue(":ksize", keySize);
    query.bindValue(":kmode", keyMode);
    query.bindValue(":etype", encryptionType);
    query.bindValue(":uuid", uuid);
    query.bindValue(":time", QDateTime::currentSecsSinceEpoch());

    if (!query.exec()) {
        qDebug() << "Failed to finalize conversation:" << query.lastError();
        return false;
    }
    return true;
}

void DatabaseManager::deleteConversation(const QByteArray &uuid)
{
    QSqlQuery query;
    query.prepare("DELETE FROM conversations "
        "WHERE conversation_uuid = :uuid");
    query.bindValue(":uuid", uuid);
    query.exec();
}

void DatabaseManager::addLastMessageToConversation(const QByteArray &uuid, const QByteArray &message, const QString &sender, qint64 timestamp)
{
    QSqlQuery query;
    query.prepare("UPDATE conversations SET last_message = :message, last_message_sender = :sender, "
                  "last_message_time = :time WHERE conversation_uuid = :uuid");
    query.bindValue(":message", message);
    query.bindValue(":sender", sender);
    query.bindValue(":time", timestamp);
    query.bindValue(":uuid", uuid);

    if (!query.exec()) {
        qDebug() << "Failed to finalize conversation:" << query.lastError();
    }
}

bool DatabaseManager::addMessage(const QByteArray &message, const QString &sender, qint64 timestamp, const QByteArray &uuid, bool uuidType)
{
    if(!uuidType && conversationExists(uuid)){
        QSqlQuery query;
        query.prepare("INSERT INTO messages (conversation_uuid, sender_nickname, timestamp, message) "
                      "VALUES (:uuid, :sender, :time, :message)");
        query.bindValue(":uuid", uuid);
        query.bindValue(":sender", sender);
        query.bindValue(":time", timestamp);
        query.bindValue(":message", message);

        if(query.exec())
        {
            return true;
        }
        else
        {
            qDebug() << "addMessage error:"
                     << query.lastError();
            return false;
        }
    } else if (uuidType && channelExists(uuid)){
        QSqlQuery query;
        query.prepare("INSERT INTO messages (channel_uuid, sender_nickname, timestamp, message) "
                      "VALUES (:uuid, :sender, :time, :message)");
        query.bindValue(":uuid", uuid);
        query.bindValue(":sender", sender);
        query.bindValue(":time", timestamp);
        query.bindValue(":message", message);

        if(query.exec())
        {
            return true;
        }
        else
        {
            qDebug() << "addMessage error:"
                     << query.lastError();
            return false;
        }
    } else {
        return false;
    }
}

bool DatabaseManager::channelExists(const QByteArray &uuid)
{
    //todo groups
    return false;
}

QString DatabaseManager::getRecipientNickname(const QString &sender, const QByteArray &conversation_uuid)
{
    QSqlQuery query;
    query.prepare("SELECT CASE WHEN sender_nickname = :sender THEN recipient_nickname "
                  "ELSE sender_nickname END AS recipient_nickname "
                  "FROM conversations WHERE conversation_uuid = :uuid");
    query.bindValue(":sender", sender);
    query.bindValue(":uuid", conversation_uuid);
    if (!query.exec()) {
        qDebug() << "Failed to load conversations:" << query.lastError().text();
        return "";
    }
    query.next();
    return query.value("recipient_nickname").toString();
}

