#ifndef CONNECTIONMANAGER_H
#define CONNECTIONMANAGER_H

#include <QObject>
#include <QSslSocket>
#include <QTimer>
#include <qaesencryption.h>
#include "qrsaencryption.h"

enum EncryptionType { RSA, AESRSA };

struct ConversationInfo {
    QString   nickname;
    QByteArray key;
    QByteArray uuid;
    QString lastMessage;
    qint64 lastMessageTime;
    int encryptionType;
    QString   lastMessageSender;
    QAESEncryption::Aes keySize;
    QAESEncryption::Mode keyMode;
};

struct EncryptedMessage{
    QByteArray message;
    QString sender;
    qint64 timestamp;
};
struct Message{
    QString message;
    QString sender;
    qint64 timestamp;
};


class ConnectionManager : public QObject
{
    Q_OBJECT
public:
    static ConnectionManager* instance();
    bool connectToServer(int timeout = 5000);
    void disconnectFromServer();
    bool sendAESKey(const QByteArray &key);
    bool sendMessage(const QString &message);
    bool sendLogInRequest(const QString &nickname, const QString &password, bool isRegistration = false);
    bool isConnected() const;
    EncryptionType getCurrentEncryptionType() const;
    void setCurrentEncryptionType(EncryptionType newCurrentEncryptionType);
    QString nickname() const;
    void getPictureData(const QString &nickname = "");
    void changePicture(const QByteArray &pictureData);
    void startConversation(const QString &nickname, bool encryptionMode,
                           QAESEncryption::Aes aesSize = QAESEncryption::AES_128, QAESEncryption::Mode aesMode = QAESEncryption::CBC);
    void getConversations();
    void getPicturesData(const QVector<QString> &nicknames);
    void setCurrentDestinationType(bool newCurrentDestinationType) {m_currentDestinationType = newCurrentDestinationType;}
    void setConversationUUID(const QByteArray &uuid) { m_currentConversationUUID = uuid;}
    void getMessages(const QByteArray &uuid);
    void setCurrentAESSize(QAESEncryption::Aes newCurrentAESSize);
    void setCurrentAESMode(QAESEncryption::Mode newCurrentAESMode);
    void setCurrentKey(const QByteArray &key);
    void updateConversations();
    void deleteConversation(const QByteArray &uuid);
public slots:
    void onConnected();
    void onDisconnected();
    void onReadyRead();
    void onConnectionTimeout();
signals:
    void connected();
    void disconnected();
    void dataReceived(const QJsonObject &JSONObject);
    void connectionTimeout();
    void logInSuccess();
    void readingError();
    void conversationsParsed(const QVector<ConversationInfo> &conversations);
    void messageDecrypted(const Message &message, const QByteArray &uuid);
private slots:
    void onSslErrors(const QList<QSslError> &errors);
private:
    explicit ConnectionManager(QObject *parent = nullptr);
    static ConnectionManager* m_instance;
    void logInContinuation();
    QByteArray generateRandomBytes(int length);
    QByteArray generateIV();
    QByteArray generateSalt();
    EncryptionType m_currentEncryptionType;
    QAESEncryption::Aes m_currentAESSize = QAESEncryption::AES_128;
    QAESEncryption::Mode m_currentAESMode = QAESEncryption::CBC;
    QSslSocket *m_socket;
    QTimer *m_connectionTimer;
    QString m_serverHost = "localhost";
    quint16 m_serverPort = 8080;
    QString m_nickname;
    QByteArray m_publicRSAKey;
    QByteArray m_privateRSAKey;
    QByteArray m_currentEncryptionKey;
    QByteArray m_currentDecryptionKey;
    QByteArray m_sessionToken;
    QByteArray m_keySalt;
    QByteArray m_password;
    QByteArray m_buffer;
    QByteArray m_currentConversationUUID;
    bool m_currentDestinationType; //0 - private message, 1 - channel message
    int m_connectionTimeout;
    qint64 m_lastConversationUpdate;
    QString encryptMessage(const QString &message);
    void processLogIn(const QJsonObject &responseJSON);
    void processConversationCreation(const QJsonObject &responseJSON);
    void processConversations(const QJsonObject &responseJSON);
    void decryptMessages(const QJsonObject &responseJSON);

    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;
    void processMessage(const QJsonObject &responseJSON);
    void decryptMessage(const QString &sender, QByteArray &encryptedMessage, const QByteArray &uuid, qint64 timestamp);
};



#endif // CONNECTIONMANAGER_H
