#include "server.h"
#include "qrsaencryption.h"

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
    QFile keyFile(":/ncrypt.key");
    keyFile.open(QIODevice::ReadOnly);
    QSslKey key(&keyFile, QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    keyFile.close();

    QFile certFile(":/ncrypt.crt");
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
    QByteArray sentSessionToken = QByteArray::fromBase64(requestJSON["sesssion_token"].toString().toUtf8());
    if(user == nullptr || user->sessionToken == QByteArray() || user->sessionToken != sentSessionToken){
        return;
    }
    QByteArray pictureData = QByteArray::fromBase64(requestJSON["picture"].toString().toUtf8());
    m_databaseManager.updatePicture(pictureData, user->nickname);
}

void Server::givePicture(const QJsonObject &requestJSON, QSslSocket *sender)
{
    QString nickname;
    QJsonObject response;
    response["response_type"] = "picture";
    if(!requestJSON.contains("nickname")){
        nickname = findUserBySocket(sender)->nickname;
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

    qDebug() << "client connected" << socket->socketDescriptor();
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
        responseJSON["challenge"] = QString(challenge.toBase64());
        responseJSON["salt"] = QString(salt.toBase64());
        responseJSON["private_key"] = QString(privateKey.toBase64());
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
        if(requestJSON["request_type"] == "log_in"){
            if(requestJSON["is_registration"] == "true") registerUser(requestJSON, socket);
            else logInUser(requestJSON, socket);
        } else if (requestJSON["request_type"] == "challenge") {
            checkChallenge(requestJSON, socket);
        } else if (requestJSON["request_type"] == "picture_change"){
            saveProfilePicture(requestJSON, socket);
        } else if (requestJSON["request_type"].toString() == "picture"){
            givePicture(requestJSON, socket);
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
