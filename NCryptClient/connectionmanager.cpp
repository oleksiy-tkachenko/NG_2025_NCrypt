#include "connectionmanager.h"
#include "QJsonObject"
#include "QJsonDocument"
#include "QRandomGenerator"
#include <QMessageBox>
#include <QApplication>
#include <QPasswordDigestor>
#include <QSslConfiguration>
#include <QJsonArray>
#include <algorithm>


ConnectionManager::ConnectionManager(QObject *parent)
    : QObject(parent){
    m_socket = new QSslSocket(this);

    connect(m_socket, &QSslSocket::encrypted, this, &ConnectionManager::onConnected);
    connect(m_socket, &QSslSocket::disconnected, this, &ConnectionManager::onDisconnected);
    connect(m_socket, &QSslSocket::readyRead, this, &ConnectionManager::onReadyRead);
    connect(m_socket, QOverload<const QList<QSslError>&>::of(&QSslSocket::sslErrors),
            this, &ConnectionManager::onSslErrors);
    QFile certFile("D:/NG_2025_Oleksii_Tkachenko/NG_2025_NCrypt/myCA.pem");
    certFile.open(QIODevice::ReadOnly);
    QSslCertificate caCert(&certFile, QSsl::Pem);
    certFile.close();

    QSslConfiguration defaultConfig = QSslConfiguration::defaultConfiguration();
    QList<QSslCertificate> caCerts = defaultConfig.caCertificates();
    caCerts.append(caCert);
    defaultConfig.setCaCertificates(caCerts);
    defaultConfig.setPeerVerifyMode(QSslSocket::VerifyPeer);
    m_socket->setSslConfiguration(defaultConfig);

    m_connectionTimer = new QTimer(this);
    m_connectionTimer->setSingleShot(true);
    connect(m_connectionTimer, &QTimer::timeout, this, &ConnectionManager::onConnectionTimeout);
    connectToServer(20000); // 20 seconds for ssl
}

void ConnectionManager::decryptMessage(const QString &sender, QByteArray &encryptedMessage, const QByteArray &uuid, qint64 timestamp)
{
    Message message;
    int encryptionType = m_currentEncryptionType;
    if(encryptionType == EncryptionType::AESRSA){
        QByteArray IV;
        QByteArray messageWithoutIV;
        QAESEncryption messageDecryptor(m_currentAESSize, m_currentAESMode);
        if(m_currentAESMode == QAESEncryption::ECB){
            IV = QByteArray();
            messageWithoutIV = encryptedMessage;
        } else {
            IV = encryptedMessage.first(16);
            messageWithoutIV = encryptedMessage.sliced(16);
        }
        message.message = QAESEncryption::RemovePadding(messageDecryptor.decode(messageWithoutIV, m_currentDecryptionKey, IV));
    } else if (encryptionType == EncryptionType::RSA){
        QRSAEncryption decryptor;
        int maxChunkSize = 190;
        if(encryptedMessage.size() > maxChunkSize){
            QByteArray delimiter = "||CHUNK||";
            while(encryptedMessage.contains(delimiter)){
                int delimiterPosition = encryptedMessage.indexOf(delimiter);
                QByteArray encryptedChunk = encryptedMessage.first(delimiterPosition);
                encryptedMessage.remove(0, delimiterPosition + delimiter.size());
                QString decryptedChunk = decryptor.decode(encryptedChunk, m_currentDecryptionKey);
                message.message += decryptedChunk;
            }
            if(!encryptedMessage.isEmpty()){
                message.message = decryptor.decode(encryptedMessage, m_currentDecryptionKey);
            }
        } else {
            message.message = decryptor.decode(encryptedMessage, m_currentDecryptionKey);
        }
    }
    message.sender = sender;
    message.timestamp = timestamp;
    emit messageDecrypted(message, uuid);
}


void ConnectionManager::processMessage(const QJsonObject &responseJSON)
{
    QString senderNickname = responseJSON["sender_nickname"].toString();
    QByteArray encryptedMessage = QByteArray::fromBase64(responseJSON["message"].toString().toUtf8());
    qint64 timestamp = responseJSON["timestamp"].toVariant().toLongLong();
    QByteArray conversationUUID = QByteArray::fromBase64(responseJSON["conversation_uuid"].toString().toUtf8());
    decryptMessage(senderNickname, encryptedMessage, conversationUUID, timestamp);
}

void ConnectionManager::onSslErrors(const QList<QSslError> &errors)
{
    qDebug() << "SSL Errors occurred (" << errors.size() << "errors):";

    bool hasUnexpectedErrors = false;

    for (const QSslError &error : errors) {
        qDebug() << "SSL Error:" << error.errorString();
        qDebug() << "Error type:" << error.error();

        if (!error.certificate().isNull()) {
            QSslCertificate cert = error.certificate();
            qDebug() << "Certificate details:";
            qDebug() << "  Subject:" << cert.subjectInfo(QSslCertificate::CommonName);
            qDebug() << "  Issuer:" << cert.issuerInfo(QSslCertificate::CommonName);
            qDebug() << "  Valid from:" << cert.effectiveDate();
            qDebug() << "  Valid to:" << cert.expiryDate();
            qDebug() << "  Serial:" << cert.serialNumber();
            qDebug() << "  Is self-signed:" << cert.isSelfSigned();
        }
        if (error.error() != QSslError::SelfSignedCertificate &&
            error.error() != QSslError::SelfSignedCertificateInChain &&
            error.error() != QSslError::CertificateUntrusted) {
            hasUnexpectedErrors = true;
        }
    }

    if (hasUnexpectedErrors) {
        qDebug() << "CRITICAL: Unexpected SSL errors";
    } else {
        qDebug() << "SSL errors are related to self-signed certificates";
    }
}

QByteArray ConnectionManager::generateRandomBytes(int length)
{
    QByteArray bytes(length, 0);
    for (int byte = 0; byte < length; byte++){
        bytes[byte] = (char)QRandomGenerator::system()->bounded(256);
    }
    return bytes;
}

QByteArray ConnectionManager::generateIV(){
    return generateRandomBytes(16);
}

QByteArray ConnectionManager::generateSalt(){
    return generateRandomBytes(16);
}

void ConnectionManager::setCurrentAESMode(QAESEncryption::Mode newCurrentAESMode)
{
    m_currentAESMode = newCurrentAESMode;
}

void ConnectionManager::setCurrentKey(const QByteArray &key)
{
    if(m_currentEncryptionType == EncryptionType::AESRSA){
        m_currentEncryptionKey = key;
        m_currentDecryptionKey = key;
    } else if (m_currentEncryptionType == EncryptionType::RSA){
        m_currentEncryptionKey = key;
        m_currentDecryptionKey = m_privateRSAKey;
    }
}

void ConnectionManager::setCurrentAESSize(QAESEncryption::Aes newCurrentAESSize)
{
    m_currentAESSize = newCurrentAESSize;
}

QString ConnectionManager::nickname() const
{
    return m_nickname;
}

void ConnectionManager::getPictureData(const QString &nickname)
{
    QJsonObject request;
    request["request_type"] = "picture";
    request["session_token"] = QString(m_sessionToken.toBase64());
    if(!nickname.isEmpty()) request["nickname"] = nickname;
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}

void ConnectionManager::getPicturesData(const QVector<QString> &nicknames)
{
    QJsonObject request;
    request["request_type"] = "pictures";
    request["session_token"] = QString(m_sessionToken.toBase64());
    QJsonArray nicknamesJSON;
    for (const QString &nickname : nicknames){
        if(nickname.isEmpty()) continue;
        nicknamesJSON.append(nickname);
    }
    request["nicknames"] = nicknamesJSON;
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}

void ConnectionManager::getMessages(const QByteArray &uuid)
{
    QJsonObject request;
    request["request_type"] = "messages";
    request["session_token"] = QString(m_sessionToken.toBase64());
    request["conversation_uuid"] = QString(uuid.toBase64());
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}

void ConnectionManager::changePicture(const QByteArray &pictureData)
{
    QJsonObject request;
    request["request_type"] = "picture_change";
    request["session_token"] = QString(m_sessionToken.toBase64());
    request["picture"] = QString(pictureData.toBase64());
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}


QString ConnectionManager::encryptMessage(const QString &message)
{
    QByteArray UTF8Message = message.toUtf8();
    switch (m_currentEncryptionType){
    case EncryptionType::RSA:{
        QRSAEncryption rsaencryption;
        // can't encrypt/decrypt if message size larger than
        // rsa key size, so splitting it
        // todo padding
        int maxChunkSize = 190;
        if (UTF8Message.size() > maxChunkSize){
            QVector<QString> encryptedChunks;
            int byteIndex = 0;
            int chunkSize = 0;
            while( byteIndex < UTF8Message.size() ){
                chunkSize = qMin(maxChunkSize, UTF8Message.size() - byteIndex);
                QByteArray chunk = UTF8Message.mid(byteIndex, chunkSize);

                QString testChunk = QString::fromUtf8(chunk);
                while (testChunk.contains(QChar::ReplacementCharacter) && chunk.size() > 0) {
                    chunk.chop(1);
                    testChunk = QString::fromUtf8(chunk);
                }


                QString encryptedChunk = rsaencryption.encode(chunk, m_currentEncryptionKey).toBase64();
                encryptedChunks.append(encryptedChunk);

                byteIndex += chunk.size();
            }

            return encryptedChunks.join("||CHUNK||");
        } else {
            return rsaencryption.encode(UTF8Message, m_currentEncryptionKey).toBase64();
        }

        }
    case EncryptionType::AESRSA:{
        QAESEncryption aesencryption(m_currentAESSize, m_currentAESMode);
        QByteArray IV;
        if (m_currentAESMode == QAESEncryption::ECB) IV = QByteArray();
        else IV = generateIV();
        QByteArray cipherText = aesencryption.encode(UTF8Message,m_currentEncryptionKey,IV);
        QString newMessage = QString((IV + cipherText).toBase64());
        return newMessage;
        }
    default:
        return "";
    }

}

ConnectionManager* ConnectionManager::m_instance = nullptr;

ConnectionManager *ConnectionManager::instance()
{
    if (!m_instance) {
        m_instance = new ConnectionManager();
    }
    return m_instance;
}

bool ConnectionManager::connectToServer(int timeout)
{
    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        qDebug() << "Already connected or connecting";
        return false;
    }
    m_connectionTimeout = timeout;

    m_connectionTimer->start(m_connectionTimeout);

    m_socket->connectToHostEncrypted(m_serverHost, m_serverPort);

    return true;
}

void ConnectionManager::disconnectFromServer()
{
    m_connectionTimer->stop();

    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        m_socket->disconnectFromHost();
    }
}

bool ConnectionManager::sendMessage(const QString &message)
{
    // todo message timeout
    if (message.isEmpty()) return false;
    QJsonObject object;
    object["request_type"] = "message";
    object["message"] = encryptMessage(message);
    object["session_token"] = QString(m_sessionToken.toBase64());
    object["destination_type"] = m_currentDestinationType;
    object["destination"] = QString(m_currentConversationUUID.toBase64());
    QJsonDocument document(object);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);

    m_socket->write(jsonData + "|EoM|");
    return true;
}

bool ConnectionManager::sendLogInRequest(const QString &nickname, const QString &password, bool isRegistration)
{
    // todo message timeout
    QJsonObject logInJSON;
    logInJSON["request_type"] = "log_in";
    m_password = password.toUtf8();
    if (isRegistration) {
        m_keySalt = generateSalt();
        QRSAEncryption keygen;
        keygen.generatePairKey(m_publicRSAKey, m_privateRSAKey);
        QByteArray passwordKey = QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256,
                                                                   m_password, m_keySalt, 50000, 32);
        QAESEncryption encryptor(QAESEncryption::AES_256, QAESEncryption::CBC);
        QByteArray keyIV =  generateIV();
        QByteArray encryptedPrivateRSAKey = encryptor.encode(m_privateRSAKey, passwordKey, keyIV);
        logInJSON["private_key"] = QString((keyIV + encryptedPrivateRSAKey).toBase64());
        logInJSON["public_key"] = QString(m_publicRSAKey.toBase64());
        logInJSON["salt"] = QString(m_keySalt.toBase64());
    }
    logInJSON["nickname"] = nickname;
    logInJSON["is_registration"] = isRegistration?"true":"false";
    QJsonDocument document(logInJSON);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);

    m_socket->write(jsonData + "|EoM|");
    m_nickname = nickname;
    return true;
}

bool ConnectionManager::isConnected() const
{
    return m_socket && m_socket->state() == QAbstractSocket::ConnectedState;
}

void ConnectionManager::onConnected()
{
    m_connectionTimer->stop();

    qDebug() << "ConnectionManager: Connected to" << m_serverHost << ":" << m_serverPort;
    emit connected();


}

void ConnectionManager::onDisconnected()
{
    m_connectionTimer->stop();

    qDebug() << "ConnectionManager: Disconnected from server";
    QMessageBox::information(nullptr, "Connection Lost",
                             "Connection to server lost. Application will exit.");

    QApplication::quit();
}


void ConnectionManager::processLogIn(const QJsonObject &responseJSON)
{
    m_keySalt = QByteArray::fromBase64(responseJSON["salt"].toString().toUtf8());
    QByteArray derivedKey = QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256, m_password, m_keySalt, 50000, 32);
    QAESEncryption decryptor(QAESEncryption::AES_256, QAESEncryption::CBC);
    QRSAEncryption RSAsign;
    QByteArray keyWithIV = QByteArray::fromBase64(responseJSON["private_key"].toString().toUtf8());
    QByteArray IV = keyWithIV.first(16);
    QByteArray privateKey = keyWithIV.sliced(16);
    m_publicRSAKey = QByteArray::fromBase64(responseJSON["public_key"].toString().toUtf8());
    m_privateRSAKey = decryptor.decode(privateKey, derivedKey, IV);
    QByteArray challenge = QByteArray::fromBase64(responseJSON["challenge"].toString().toUtf8());;
    QByteArray signedChallenge = RSAsign.signMessage(challenge, m_privateRSAKey);
    QJsonObject logInJSON;
    logInJSON["request_type"] = "challenge";
    logInJSON["challenge"] = QString(signedChallenge.toBase64());
    QJsonDocument document(logInJSON);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);

    m_socket->write(jsonData + "|EoM|");
}

void ConnectionManager::startConversation(const QString &nickname, bool encryptionMode,
                                          QAESEncryption::Aes aesSize, QAESEncryption::Mode aesMode)
{
    QJsonObject request;
    m_currentEncryptionType = EncryptionType(encryptionMode);
    m_currentAESSize = aesSize;
    m_currentAESMode = aesMode;
    request["request_type"] = "create_conversation";
    request["session_token"] = QString(m_sessionToken.toBase64());
    request["recipient"] = nickname;
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}

void ConnectionManager::getConversations()
{
    QJsonObject request;
    request["request_type"] = "conversations";
    request["session_token"] = QString(m_sessionToken.toBase64());
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
    m_lastConversationUpdate = QDateTime::currentSecsSinceEpoch();
}

void ConnectionManager::updateConversations()
{
    QJsonObject request;
    request["request_type"] = "update_conversations";
    request["last_update"] = m_lastConversationUpdate;
    request["session_token"] = QString(m_sessionToken.toBase64());
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}

void ConnectionManager::deleteConversation(const QByteArray &uuid)
{
    QJsonObject request;
    request["request_type"] = "delete_conversation";
    request["conversation_uuid"] = QString(uuid.toBase64());
    request["session_token"] = QString(m_sessionToken.toBase64());
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}

void ConnectionManager::processConversationCreation(const QJsonObject &responseJSON)
{
    QJsonObject request;
    m_currentConversationUUID = QByteArray::fromBase64(responseJSON["conversation_uuid"].toString().toUtf8());
    if( m_currentEncryptionType == EncryptionType::AESRSA){
        QRSAEncryption encryptor;
        QByteArray aesKey = generateRandomBytes(8*(2+(int)m_currentAESSize));
        m_currentEncryptionKey = aesKey;
        m_currentDecryptionKey = aesKey;
        QByteArray recipientPublicKey = QByteArray::fromBase64(responseJSON["public_key"].toString().toUtf8());
        QByteArray encryptedRecipientAesKey = encryptor.encode(aesKey, recipientPublicKey);
        QByteArray encryptedSenderAesKey = encryptor.encode(aesKey, m_publicRSAKey);
        request["sender_key"] = QString(encryptedSenderAesKey.toBase64());
        request["recipient_key"] = QString(encryptedRecipientAesKey.toBase64());
        request["key_size"] = (int)m_currentAESSize;
        request["key_mode"] = (int)m_currentAESMode;
    } else {
        request["recipient_nickname"] = responseJSON["recipient_nickname"];
    }
    request["request_type"] = "conversation_keys";
    request["conversation_uuid"] = QString(m_currentConversationUUID.toBase64());
    request["encryption_type"] = (int)m_currentEncryptionType;
    request["session_token"] = QString(m_sessionToken.toBase64());
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}

void ConnectionManager::processConversations(const QJsonObject &responseJSON)
{
    QJsonArray conversationsJSON = responseJSON["conversations"].toArray();
    QVector<ConversationInfo> conversations;
    for(const QJsonValue &value : conversationsJSON){
        if (!value.isObject()) continue;
        QJsonObject conversation = value.toObject();
        QString nickname = conversation["nickname"].toString();
        QByteArray uuid = QByteArray::fromBase64(conversation["uuid"].toString().toUtf8());
        QByteArray conversationKey = QByteArray::fromBase64(conversation["key"].toString().toUtf8());
        QAESEncryption::Mode aesMode = m_currentAESMode;
        QAESEncryption::Aes aesSize = m_currentAESSize;
        QByteArray lastMessageEncrypted = QByteArray::fromBase64(conversation["last_message"].toString().toUtf8());
        QString lastMessage = "";
        int encryptionType = conversation["encryption_type"].toInt();
        if(encryptionType){
            QByteArray keyEncrypted = QByteArray::fromBase64(conversation["key"].toString().toUtf8());
            QRSAEncryption keyDecryptor;
            conversationKey = keyDecryptor.decode(keyEncrypted, m_privateRSAKey);
            aesSize = QAESEncryption::Aes(conversation["key_size"].toInt());
            aesMode = QAESEncryption::Mode(conversation["key_mode"].toInt());
            if(!lastMessageEncrypted.isEmpty()){
                QByteArray IV;
                QByteArray messageWithoutIV;
                QAESEncryption messageDecryptor(aesSize, aesMode);
                if(aesMode == QAESEncryption::ECB){
                    IV = QByteArray();
                    messageWithoutIV = lastMessageEncrypted;
                } else {
                    IV = lastMessageEncrypted.first(16);
                    messageWithoutIV = lastMessageEncrypted.sliced(16);
                }
                lastMessage = QAESEncryption::RemovePadding(messageDecryptor.decode(messageWithoutIV, conversationKey, IV));
            }
        } else if (!encryptionType){
            QRSAEncryption decryptor;
            int maxChunkSize = 190;
            if(lastMessageEncrypted.size() > maxChunkSize){
                QByteArray delimiter = "||CHUNK||";
                while(lastMessageEncrypted.contains(delimiter)){
                    int delimiterPosition = lastMessageEncrypted.indexOf(delimiter);
                    QByteArray encryptedChunk = lastMessageEncrypted.first(delimiterPosition);
                    lastMessageEncrypted.remove(0, delimiterPosition + delimiter.size());
                    QString decryptedChunk = decryptor.decode(encryptedChunk, m_privateRSAKey);
                    lastMessage += decryptedChunk;
                }
            } else {
                lastMessage = decryptor.decode(lastMessageEncrypted, m_privateRSAKey);
            }
        }
        QString lastMessageSender = conversation["last_message_sender"].toString();
        qint64 lastMessageTime = conversation["last_message_time"].toInt();
        ConversationInfo thisConversation;
        thisConversation.nickname = nickname;
        thisConversation.key = conversationKey;
        thisConversation.uuid = uuid;
        thisConversation.keySize = aesSize;
        thisConversation.keyMode = aesMode;
        thisConversation.encryptionType = encryptionType;
        thisConversation.lastMessage = lastMessage;
        thisConversation.lastMessageTime = lastMessageTime;
        thisConversation.lastMessageSender = lastMessageSender;
        conversations.push_back(thisConversation);
    }
    emit conversationsParsed(conversations);
}

void ConnectionManager::decryptMessages(const QJsonObject &responseJSON)
{
    QJsonArray messagesJSON = responseJSON["messages"].toArray();
    if (messagesJSON.isEmpty()) return;
    QVector<EncryptedMessage> messages;
    // transforming from json to vector to then sort
    for(const QJsonValue &value : messagesJSON){
        if (!value.isObject()) continue;
        QJsonObject messageJSON = value.toObject();
        QByteArray encryptedMessage = QByteArray::fromBase64(messageJSON["message"].toString().toUtf8());
        QString sender = messageJSON["sender"].toString();
        qint64 timestamp = messageJSON["timestamp"].toVariant().toLongLong();
        EncryptedMessage message;
        message.message = encryptedMessage;
        message.sender = sender;
        message.timestamp = timestamp;
        messages.append(message);
    }

    std::sort(messages.begin(), messages.end(),
              [](const EncryptedMessage &a, const EncryptedMessage &b) {
                return a.timestamp < b.timestamp; });

    for(EncryptedMessage &encryptedMessage : messages){
        decryptMessage(encryptedMessage.sender, encryptedMessage.message, m_currentConversationUUID, encryptedMessage.timestamp);
    }
}

void ConnectionManager::onReadyRead()
{
    m_buffer.append(m_socket->readAll());
    QByteArray delimiter = "|EoM|";
    while(m_buffer.contains(delimiter)){
        int delimiterPosition = m_buffer.indexOf(delimiter);
        QByteArray data = m_buffer.first(delimiterPosition);
        m_buffer.remove(0, delimiterPosition + delimiter.size());
        QJsonParseError err;
        QJsonDocument JSONDoc = QJsonDocument::fromJson(data, &err);
        if (err.error != QJsonParseError::NoError) {
            qDebug() << "Invalid JSON: " << err.errorString();
            emit readingError();
            return;
        }
        QJsonObject responseJSON = JSONDoc.object();
        QString responseType = responseJSON["response_type"].toString();
        if(responseType == "log_in" && !responseJSON.contains("log_in_error_msg")){
            processLogIn(responseJSON);
        } else if (responseType == "challenge" || responseType == "registration"){
            if(responseJSON.contains("session_token")){
                m_sessionToken = QByteArray::fromBase64(responseJSON["session_token"].toString().toUtf8());
            }
        } else if (responseType == "conversation_creation" && !responseJSON.contains("error_msg")){
            processConversationCreation(responseJSON);
        } else if (responseType == "conversations_changed") {
            updateConversations();
        } else if (responseType == "conversations"){
            processConversations(responseJSON);
        } else if (responseType == "messages"){
            decryptMessages(responseJSON);
        } else if (responseType == "message"){
            processMessage(responseJSON);
        }
        emit dataReceived(responseJSON);
    }
}

void ConnectionManager::onConnectionTimeout()
{
    qDebug() << "ConnectionManager: Connection timeout";

    m_socket->abort();
    emit connectionTimeout();
}

EncryptionType ConnectionManager::getCurrentEncryptionType() const
{
    return m_currentEncryptionType;
}

void ConnectionManager::setCurrentEncryptionType(EncryptionType newCurrentEncryptionType)
{
    m_currentEncryptionType = newCurrentEncryptionType;
}


