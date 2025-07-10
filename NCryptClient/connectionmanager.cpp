#include "connectionmanager.h"
#include "QJsonObject"
#include "QJsonDocument"
#include "QRandomGenerator"
#include <QMessageBox>
#include <QApplication>
#include <QPasswordDigestor>
#include <QSslConfiguration>


ConnectionManager::ConnectionManager(QObject *parent)
    : QObject(parent){
    m_socket = new QSslSocket(this);

    connect(m_socket, &QSslSocket::encrypted, this, &ConnectionManager::onConnected);
    connect(m_socket, &QSslSocket::disconnected, this, &ConnectionManager::onDisconnected);
    connect(m_socket, &QSslSocket::readyRead, this, &ConnectionManager::onReadyRead);
    QFile certFile(":/ncrypt.crt");
    certFile.open(QIODevice::ReadOnly);
    QSslCertificate caCert(&certFile, QSsl::Pem);
    certFile.close();

    QSslConfiguration config = m_socket->sslConfiguration();
    QList<QSslCertificate> caCerts = config.caCertificates();
    caCerts.append(caCert);
    config.setCaCertificates(caCerts);
    m_socket->setSslConfiguration(config);

    m_connectionTimer = new QTimer(this);
    m_connectionTimer->setSingleShot(true);
    connect(m_connectionTimer, &QTimer::timeout, this, &ConnectionManager::onConnectionTimeout);
}

QByteArray ConnectionManager::generateRandomBytes(int length)
{
    QByteArray bytes(length, 0);
    for (int byte = 0; byte < length; byte++){
        bytes[byte] = (char)QRandomGenerator::global()->bounded(256);
    }
    return bytes;
}

QByteArray ConnectionManager::generateIV(){
    return generateRandomBytes(16);
}

QByteArray ConnectionManager::generateSalt(){
    return generateRandomBytes(16);
}

QString ConnectionManager::nickname() const
{
    return m_nickname;
}

void ConnectionManager::getPictureData()
{
    QJsonObject request;
    request["request_type"] = "picture";
    request["session_token"] = QString(m_sessionToken.toBase64());
    QJsonDocument document(request);
    QByteArray jsonData = document.toJson(QJsonDocument::Compact);
    m_socket->write(jsonData + "|EoM|");
}

QString ConnectionManager::encryptMessage(const QString &message)
{
    QByteArray UTF8Message = message.toUtf8();
    switch (m_currentEncryptionType){
    case RSA:{
        QRSAEncryption rsaencryption(m_currentRSASize);
        // can't encrypt/decrypt if message size larger than
        // rsa key size, so splitting it
        // todo padding
        int maxChunkSize = m_currentRSASize/8 - 66;
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
    case AESRSA:{
        QAESEncryption aesencryption(m_currentAESSize, m_currentAESMode);
        QByteArray IV = generateIV();
        return QString((IV + aesencryption.encode(UTF8Message,m_currentEncryptionKey,IV)).toBase64());
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

bool ConnectionManager::connectToServer(const QString &host, quint16 port, int timeout)
{
    if (m_socket->state() != QAbstractSocket::UnconnectedState) {
        qDebug() << "Already connected or connecting";
        return false;
    }
    m_serverHost = host;
    m_serverPort = port;
    m_connectionTimeout = timeout;

    m_connectionTimer->start(m_connectionTimeout);

    m_socket->connectToHostEncrypted(host, port);

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
    QJsonObject object;
    object["request_type"] = "message";
    object["message"] = encryptMessage(message);
    object["session_token"] = QString(m_sessionToken);
    object["destination_type"] = m_currentDestinationType;
    object["destination"] = QString(m_currentDestination);
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
    QByteArray publicRSAKey;
    m_password = password.toUtf8();
    if (isRegistration) {
        m_keySalt = generateSalt();
        QRSAEncryption keygen;
        keygen.generatePairKey(publicRSAKey, m_privateRSAKey);
        QByteArray passwordKey = QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256,
                                                                   m_password, m_keySalt, 50000, 32);
        QAESEncryption encryptor(QAESEncryption::AES_256, QAESEncryption::CBC);
        QByteArray keyIV =  generateIV();
        QByteArray encryptedPrivateRSAKey = encryptor.encode(m_privateRSAKey, passwordKey, keyIV);
        logInJSON["private_key"] = QString((keyIV + encryptedPrivateRSAKey).toBase64());
        logInJSON["public_key"] = QString(publicRSAKey.toBase64());
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


void ConnectionManager::processLogIn(QJsonObject responseJSON)
{
    m_keySalt = QByteArray::fromBase64(responseJSON["salt"].toString().toUtf8());
    QByteArray derivedKey = QPasswordDigestor::deriveKeyPbkdf2(QCryptographicHash::Sha256, m_password, m_keySalt, 50000, 32);
    QAESEncryption decryptor(QAESEncryption::AES_256, QAESEncryption::CBC);
    QRSAEncryption RSAsign;
    QByteArray keyWithIV = QByteArray::fromBase64(responseJSON["private_key"].toString().toUtf8());
    QByteArray IV = keyWithIV.first(16);
    QByteArray privateKey = keyWithIV.sliced(16);
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
        if(responseJSON["response_type"] == "log_in" && !responseJSON.contains("log_in_error_msg")){
            processLogIn(responseJSON);
        } else if (responseJSON["response_type"] == "challenge" || responseJSON["response_type"] == "registration"){
            if(responseJSON.contains("session_token")){
                m_sessionToken = QByteArray::fromBase64(responseJSON["session_token"].toString().toUtf8());
            }
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

encryptionType ConnectionManager::getCurrentEncryptionType() const
{
    return m_currentEncryptionType;
}

void ConnectionManager::setCurrentEncryptionType(encryptionType newCurrentEncryptionType)
{
    m_currentEncryptionType = newCurrentEncryptionType;
}


