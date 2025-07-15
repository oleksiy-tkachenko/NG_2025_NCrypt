#include "server.h"
#include "qrsaencryption.h"

#include <QJsonArray>
#include <QJsonObject>
#include <QJsonParseError>
#include <QRandomGenerator>
#include <QSslKey>
Server::Server()
{
    if (this->listen(QHostAddress::AnyIPv4,8080)){
        setupSsl();
        qDebug() << "started";
    } else {
        qDebug() << "error starting";
    }
}

void Server::setupSsl()
{
    QFile keyFile("D:/NG_2025_Oleksii_Tkachenko/NG_2025_NCrypt/ncrypt.key");
    keyFile.open(QIODevice::ReadOnly);
    QSslKey key(&keyFile, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    keyFile.close();

    QFile certFile("D:/NG_2025_Oleksii_Tkachenko/NG_2025_NCrypt/ncrypt.crt");
    certFile.open(QIODevice::ReadOnly);
    QSslCertificate cert(&certFile, QSsl::Pem);
    certFile.close();

    QSslConfiguration defaultConfig = QSslConfiguration::defaultConfiguration();
    defaultConfig.setPrivateKey(key);
    defaultConfig.setLocalCertificate(cert);
    defaultConfig.setPeerVerifyMode(QSslSocket::VerifyNone);

    QSslConfiguration::setDefaultConfiguration(defaultConfig);
}

void Server::sendMessage(QString message, QSslSocket *socket)
{
    m_Data.clear();
    QDataStream out(&m_Data, QDataStream::WriteOnly);
    out.setVersion(QDataStream::Qt_6_7);
    out << message;
    socket->write(m_Data);
}



void Server::registerUser(const QJsonObject &requestJSON, QSslSocket* sender)
{
    QJsonObject responseJSON;
    responseJSON["response_type"] = "registration";
    QString nickname = requestJSON["nickname"].toString().toLower();
    static QRegularExpression correctNicknameRE("^[a-z0-9_.-]+$");
    if(!correctNicknameRE.match(nickname).hasMatch()){
        responseJSON["log_in_error_msg"] = "Incorrect username, using forbidden symbols";
        return;
    } else if (nickname.length() > 32 || nickname.length() < 2){
        responseJSON["log_in_error_msg"] = "Incorrect username, too short or too long";
        return;
    }
    QByteArray salt = QByteArray::fromBase64(requestJSON["salt"].toString().toUtf8());
    QByteArray publicKey = QByteArray::fromBase64(requestJSON["public_key"].toString().toUtf8());
    QByteArray privateKey = QByteArray::fromBase64(requestJSON["private_key"].toString().toUtf8());
    if(m_databaseManager.userExists(nickname)){
        responseJSON["log_in_error_msg"] = "There is already a user with this nickname";
    } else if(!m_databaseManager.addUser(nickname, salt, publicKey, privateKey)){
        responseJSON["log_in_error_msg"] = "Unexpected error, try again";
    } else {
        QByteArray sessionToken = generateSessionToken();
        responseJSON["session_token"] = QString(sessionToken.toBase64());
        m_users.push_back(User{sender, nickname, sessionToken, QByteArray()});
    }
    QJsonDocument document(responseJSON);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);

    sender->write(jsonData + "|EoM|");
}

QByteArray Server::generateRandomBytes(int length) {
    QByteArray bytes(length, 0);
    for (int byte = 0; byte < length; byte++) {
        bytes[byte] = (char)QRandomGenerator::global()->bounded(256);
    }
    return bytes;
}
QByteArray Server::generateSessionToken() { return generateRandomBytes(32); }
QByteArray Server::generateChallenge() { return generateRandomBytes(32); }

void Server::checkChallenge(const QJsonObject &requestJSON, QSslSocket *sender)
{
    QJsonObject responseJSON;
    responseJSON["response_type"] = "challenge";
    QByteArray challenge = QByteArray::fromBase64(requestJSON["challenge"].toString().toUtf8());
    User *user = findUserBySocket(sender);
    if (user == nullptr) return;
    QString nickname = user->nickname;
    QByteArray publicKey = m_databaseManager.getUserValue(nickname, "public_key");
    QRSAEncryption verifier;
    if(!verifier.checkSignMessage(challenge, publicKey)){
        responseJSON["challenge_status"] = "wrong";
        responseJSON["log_in_error_msg"] = "Incorrect nickname or password";
    }
    else{
        QByteArray sessionToken = generateSessionToken();
        responseJSON["challenge_status"] = "correct";
        responseJSON["session_token"] = QString(sessionToken.toBase64());
        user->sessionToken = sessionToken;
        user->currentChallenge = QByteArray(); // no challenge
    }
    QJsonDocument document(responseJSON);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);

    sender->write(jsonData + "|EoM|");
}

User* Server::findUserBySocket(QSslSocket *sender)
{
    for (User& user : m_users) {
        if (user.socket == sender) {
            return &user;
        }
    }
    return nullptr;
}

void Server::saveProfilePicture(const QJsonObject &requestJSON, QSslSocket *sender)
{
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;
    QByteArray pictureData = QByteArray::fromBase64(requestJSON["picture"].toString().toUtf8());
    m_databaseManager.updatePicture(pictureData, user->nickname);
}

bool Server::isSessionTokenCorrect(QByteArray sentSessionToken, User* user){

    if(user == nullptr || user->sessionToken == QByteArray() || user->sessionToken != sentSessionToken){
        return false;
    }
    return true;
}

void Server::createConversation(const QJsonObject &requestJSON, QSslSocket *sender)
{
    QJsonObject response;
    response["response_type"] = "conversation_creation";
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;
    QString senderNickname = user->nickname;
    QString recipientNickname = requestJSON["recipient"].toString();
    if(!m_databaseManager.userExists(recipientNickname)){
        response["error_msg"] = "No user with this nickname";
    } else {
        if(m_databaseManager.conversationExists(senderNickname, recipientNickname)) {
            response["error_msg"] = "Conversation with this user already exists";
        } else {
            QByteArray conversationIdentifier = QUuid::createUuid().toRfc4122();
            if(!m_databaseManager.createConversation(senderNickname, recipientNickname, conversationIdentifier)) {
                response["error_msg"] = "Unexpected error with server, try again";
            } else {
                QByteArray recipientPublicKey = m_databaseManager.getUserValue(recipientNickname, "public_key");
                response["conversation_uuid"] = QString(conversationIdentifier.toBase64());
                response["public_key"] = QString(recipientPublicKey.toBase64());
                response["recipient_nickname"] = recipientNickname;
            }
        }
    }
    QJsonDocument document(response);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    sender->write(jsonData + "|EoM|");
}

void Server::completeConversation(const QJsonObject &requestJSON, QSslSocket *sender)
{
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;
    QByteArray conversationUUID = QByteArray::fromBase64(requestJSON["conversation_uuid"].toString().toUtf8());
    if(!m_databaseManager.conversationExists(conversationUUID)) return;
    if(!m_databaseManager.senderPresent(user->nickname, conversationUUID)) return;
    int encryptionType = requestJSON["encryption_type"].toInt();
    int keySize = 0;
    int keyMode = 0;
    QByteArray senderKey;
    QByteArray recipientKey;
    QString recipientNickname = requestJSON["recipient_nickname"].toString();
    if(encryptionType){
        senderKey = QByteArray::fromBase64(requestJSON["sender_key"].toString().toUtf8());
        recipientKey = QByteArray::fromBase64(requestJSON["recipient_key"].toString().toUtf8());
        if (senderKey.isEmpty() || recipientKey.isEmpty()) {
            m_databaseManager.deleteConversation(conversationUUID);
            return;
        }
        keySize = requestJSON["key_size"].toInt();
        keyMode = requestJSON["key_mode"].toInt();
        if(!m_databaseManager.finalizeConversation(senderKey, recipientKey, keySize, keyMode, encryptionType, conversationUUID)) {
            m_databaseManager.deleteConversation(conversationUUID);
            return;
        }
    } else {
        recipientKey = m_databaseManager.getUserValue(user->nickname, "public_key");
        senderKey = m_databaseManager.getUserValue(recipientNickname, "public_key");
        if(!m_databaseManager.finalizeConversation(senderKey, recipientKey, 0, 0, encryptionType, conversationUUID)) {
            m_databaseManager.deleteConversation(conversationUUID);
            return;
        }
    }
    QJsonObject response;
    response["response_type"] = "conversation_complete";
    QJsonDocument document(response);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    sender->write(jsonData + "|EoM|");

    QSslSocket *recipientSocket;
    if(isRecipientOnline(recipientNickname, recipientSocket)){
        QJsonObject responseToRecipient;
        responseToRecipient["response_type"] = "conversations_changed";
        QJsonDocument document(responseToRecipient);
        QByteArray jsonData = document.toJson(QJsonDocument::Compact);
        recipientSocket->write(jsonData + "|EoM|");
    }
}

void Server::giveConversations(const QJsonObject &requestJSON, QSslSocket *sender, bool fetchNew)
{
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;
    QVector<ConversationInfo> conversations;
    if(!fetchNew){
        conversations = m_databaseManager.getConversations(user->nickname);
    } else {
        qint64 lastConversationsUpdateTime = requestJSON["last_update"].toVariant().toLongLong();
        conversations = m_databaseManager.getConversations(user->nickname, true, lastConversationsUpdateTime);
    }
    if(conversations.empty()) return;
    QJsonObject response;
    QJsonArray conversationsJSON;
    for(const ConversationInfo &conversation : conversations){
        conversationsJSON.append(createConversationJSON(conversation));
    }
    response["response_type"] = "conversations";
    response["conversations"] = conversationsJSON;
    QJsonDocument document(response);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    sender->write(jsonData + "|EoM|");
}

QJsonObject Server::createConversationJSON(const ConversationInfo &conversation){
    QJsonObject conversationJSON;
    conversationJSON["nickname"] = conversation.nickname;
    conversationJSON["key"] = QString(conversation.key.toBase64());
    conversationJSON["uuid"] = QString(conversation.uuid.toBase64());
    conversationJSON["key_mode"] = conversation.keyMode;
    conversationJSON["key_size"] = conversation.keySize;
    conversationJSON["encryption_type"] = conversation.encryptionType;
    conversationJSON["last_message"] = QString(conversation.lastMessage.toBase64());
    conversationJSON["last_message_sender"] = conversation.lastMessageSender;
    conversationJSON["last_message_time"] = conversation.lastMessageTime;
    return conversationJSON;
}

void Server::givePictures(const QJsonObject &requestJSON, QSslSocket *sender)
{
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;
    QJsonArray nicknames = requestJSON["nicknames"].toArray();
    if(nicknames.isEmpty()) return;
    QJsonObject response;
    QJsonArray pictures = QJsonArray();
    for(const QJsonValue &value : nicknames){
        QString nickname = value.toString();
        if (nickname.isEmpty() || !m_databaseManager.userExists(nickname)) return;
        QByteArray pictureData = m_databaseManager.getUserValue(nickname, "picture");
        QJsonObject pictureWithName;
        pictureWithName["nickname"] = nickname;
        pictureWithName["picture"] = QString(pictureData.toBase64());
        pictures.append(pictureWithName);
    }
    response["response_type"] = "pictures";
    response["pictures"] = pictures;
    QJsonDocument document(response);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    sender->write(jsonData + "|EoM|");
}

void Server::giveMessages(const QJsonObject &requestJSON, QSslSocket *sender)
{
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;;
    QByteArray uuid = QByteArray::fromBase64(requestJSON["conversation_uuid"].toString().toUtf8());
    if(!m_databaseManager.senderPresent(user->nickname, uuid)) return;
    QVector<Message> messages = m_databaseManager.getMessages(uuid);
    QJsonArray messagesJSON;
    for(const Message &message : messages){
        QJsonObject messageJSON;
        messageJSON["message"] = QString(message.message.toBase64());
        messageJSON["sender"] = message.sender;
        messageJSON["timestamp"] = message.timestamp;
        messagesJSON.append(messageJSON);
    }
    QJsonObject response;
    response["response_type"] = "messages";
    response["messages"] = messagesJSON;
    QJsonDocument document(response);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    sender->write(jsonData + "|EoM|");
}

void Server::processMessage(const QJsonObject &requestJSON, QSslSocket *sender)
{
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;
    bool destinationType = requestJSON["destination_type"].toInt();
    QByteArray destination = QByteArray::fromBase64(requestJSON["destination"].toString().toUtf8());
    QByteArray message = QByteArray::fromBase64(requestJSON["message"].toString().toUtf8());
    if(message.isEmpty()) return;
    QString senderNickname = user->nickname;
    if(!m_databaseManager.senderPresent(senderNickname, destination)) return;
    qint64 timestamp = QDateTime::currentSecsSinceEpoch();
    if(!m_databaseManager.addMessage(message, senderNickname, timestamp, destination, destinationType)) return;
    if(!destinationType) {
        m_databaseManager.addLastMessageToConversation(destination, message, senderNickname, timestamp);
        QString recipientNickname = m_databaseManager.getRecipientNickname(senderNickname, destination);
        QSslSocket *recipientSocket;
        if(isRecipientOnline(recipientNickname, recipientSocket)){
            QJsonObject response;
            response["response_type"] = "message";
            response["message"] = QString(message.toBase64());
            response["conversation_uuid"] = QString(destination.toBase64());
            response["timestamp"] = timestamp;
            response["sender_nickname"] = senderNickname;
            QJsonDocument document(response);
            QByteArray jsonData = document.toJson(QJsonDocument::Compact);
            recipientSocket->write(jsonData + "|EoM|");

            response = QJsonObject();
            response["response_type"] = "conversations_changed";
            document = QJsonDocument(response);
            jsonData = document.toJson(QJsonDocument::Compact);
            recipientSocket->write(jsonData + "|EoM|");
        }
    } else {
        //todo groups
    }
}

bool Server::isRecipientOnline(const QString &recipientNickname, QSslSocket *&recipientSocket){
    bool online = false;
    for(const User &user : m_users){
        if(user.nickname == recipientNickname){ // checking if user is online to send message immediately
            online = true;
            recipientSocket = user.socket;
            break;
        }
    }
    return online;
}

void Server::deleteConversation(const QJsonObject &requestJSON, QSslSocket *sender)
{
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;
    QString senderNickname = user->nickname;
    QByteArray uuid = QByteArray::fromBase64(requestJSON["conversation_uuid"].toString().toUtf8());
    if(!m_databaseManager.senderPresent(senderNickname, uuid)) return;
    QString recipientNickname = m_databaseManager.getRecipientNickname(senderNickname, uuid);
    m_databaseManager.deleteConversation(uuid);
    QSslSocket* recipientSocket;
    if(isRecipientOnline(recipientNickname, recipientSocket)){
        QJsonObject response;
        response["response_type"] = "conversation_deleted";
        response["conversation_uuid"] = requestJSON["conversation_uuid"];
        QJsonDocument document(response);
        QByteArray jsonData = document.toJson(QJsonDocument::Compact);
        recipientSocket->write(jsonData + "|EoM|");
    }
}

void Server::givePicture(const QJsonObject &requestJSON, QSslSocket *sender)
{
    User* user = findUserBySocket(sender);
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["session_token"].toString().toUtf8());
    if(!isSessionTokenCorrect(sentSessionToken, user)) return;
    QString nickname;
    QJsonObject response;
    response["response_type"] = "picture";
    if(!requestJSON.contains("nickname")){
        nickname = user->nickname;
    } else {
        nickname = requestJSON["nickname"].toString();
        response["nickname"] = nickname;
    }
    if (nickname.isEmpty()) return;
    if(!m_databaseManager.userExists(nickname)) return;
    response["picture"] = QString(m_databaseManager.getUserValue(nickname, "picture").toBase64());
    QJsonDocument document(response);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    sender->write(jsonData + "|EoM|");
}

void Server::incomingConnection(qintptr socketDescriptor)
{
    QSslSocket* socket = new QSslSocket;
    if (socket->setSocketDescriptor(socketDescriptor)) {
        addPendingConnection(socket);
        connect(socket, &QSslSocket::encrypted, this, &Server::onEncrypted);
        qDebug() << "client connected" << socketDescriptor;
        socket->startServerEncryption();
    } else {
        delete socket;
    }
}

void Server::onEncrypted()
{
    QSslSocket* socket = (QSslSocket*)sender();
    connect(socket, &QSslSocket::readyRead, this , &Server::slotReadyRead);
    connect(socket, &QSslSocket::disconnected, this, &Server::onClientDisconnect);

    qDebug() << "client encrypted succesfully" << socket->socketDescriptor();
}

void Server::logInUser(const QJsonObject &requestJSON, QSslSocket *sender)
{
    QJsonObject responseJSON;
    responseJSON["response_type"] = "log_in";
    QString nickname = requestJSON["nickname"].toString().toLower();
    if(!m_databaseManager.userExists(nickname)){
        responseJSON["log_in_error_msg"] = "There is no user with this nickname";
    } else {
        QByteArray challenge = generateChallenge();
        QByteArray salt = m_databaseManager.getUserValue(nickname, "salt");
        QByteArray privateKey = m_databaseManager.getUserValue(nickname, "private_key");
        QByteArray publicKey = m_databaseManager.getUserValue(nickname, "public_key");
        responseJSON["challenge"] = QString(challenge.toBase64());
        responseJSON["salt"] = QString(salt.toBase64());
        responseJSON["private_key"] = QString(privateKey.toBase64());
        responseJSON["public_key"] = QString(publicKey.toBase64());
        m_users.append(User{sender, nickname, QByteArray(), challenge});
    }
    QJsonDocument document(responseJSON);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);

    sender->write(jsonData + "|EoM|");
}


void Server::slotReadyRead()
{
    QSslSocket* socket = (QSslSocket*)sender();
    QByteArray &buffer = m_socketBufferHash[socket];

    buffer.append(socket->readAll());
    QByteArray delimiter = "|EoM|";
    while(buffer.contains(delimiter)){
        int delimiterPosition = buffer.indexOf(delimiter);
        QByteArray data = buffer.first(delimiterPosition);
        buffer.remove(0, delimiterPosition + delimiter.size());
        QJsonParseError err;
        QJsonDocument JSONDoc = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qWarning() << "Invalid JSON: " << err.errorString();
            return;
        }
        QJsonObject requestJSON = JSONDoc.object();
        QString requestType = requestJSON["request_type"].toString();
        if(requestType == "log_in"){
            if(requestJSON["is_registration"] == "true") registerUser(requestJSON, socket);
            else logInUser(requestJSON, socket);
        } else if (requestType == "challenge") {
            checkChallenge(requestJSON, socket);
        } else if (requestType == "picture_change"){
            saveProfilePicture(requestJSON, socket);
            givePicture(requestJSON, socket);
        } else if (requestType == "picture"){
            givePicture(requestJSON, socket);
        } else if (requestType == "create_conversation"){
            createConversation(requestJSON, socket);
        } else if (requestType == "conversation_keys"){
            completeConversation(requestJSON, socket);
        } else if (requestType == "conversations"){
            giveConversations(requestJSON, socket);
        } else if (requestType == "update_conversations") {
            giveConversations(requestJSON, socket, true);
        } else if (requestType == "pictures"){
            givePictures(requestJSON, socket);
        } else if (requestType == "messages"){
            giveMessages(requestJSON, socket);
        } else if (requestType == "message"){
            processMessage(requestJSON, socket);
        } else if (requestType == "delete_conversation"){
            deleteConversation(requestJSON, socket);
        }
    }
}

// cleaning up
void Server::onClientDisconnect()
{
    QSslSocket* socket = (QSslSocket*)sender();
    m_socketBufferHash.remove(socket);

    for (int i = 0; i < m_users.size(); i++) {
        if (m_users[i].socket == socket) {
            m_users.removeAt(i);
            break;
        }
    }

    qDebug() << "client disconnected" << socket->socketDescriptor();
    socket->deleteLater();
}
