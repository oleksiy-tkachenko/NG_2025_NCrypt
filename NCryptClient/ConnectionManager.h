#ifndef CONNECTIONMANAGER_H
#define CONNECTIONMANAGER_H

#include <QObject>
#include <QSslSocket>
#include <QTimer>
#include <qaesencryption.h>
#include "qrsaencryption.h"

enum encryptionType { RSA = 1, AESRSA = 2 };

class ConnectionManager : public QObject
{
    Q_OBJECT
public:
    static ConnectionManager* instance();
    bool connectToServer(const QString &host, quint16 port, int timeout = 5000);
    void disconnectFromServer();
    bool sendAESKey(const QByteArray &key);
    bool sendMessage(const QString &message);
    bool sendLogInRequest(const QString &nickname, const QString &password, bool isRegistration = false);
    bool isConnected() const;
    encryptionType getCurrentEncryptionType() const;
    void setCurrentEncryptionType(encryptionType newCurrentEncryptionType);


    QString nickname() const;

    void getPictureData();
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
private slots:
    void onSslErrors(const QList<QSslError> &errors);
private:
    explicit ConnectionManager(QObject *parent = nullptr);
    static ConnectionManager* m_instance;
    void logInContinuation();
    QByteArray generateRandomBytes(int length);
    QByteArray generateIV();
    QByteArray generateSalt();
    encryptionType m_currentEncryptionType;
    QRSAEncryption::Rsa m_currentRSASize = QRSAEncryption::RSA_2048;
    QAESEncryption::Aes m_currentAESSize = QAESEncryption::AES_128;
    QAESEncryption::Mode m_currentAESMode = QAESEncryption::CBC;
    QSslSocket *m_socket;
    QTimer *m_connectionTimer;
    QString m_serverHost;
    quint16 m_serverPort;
    QString m_nickname;
    QByteArray m_privateRSAKey;
    QByteArray m_currentEncryptionKey;
    QByteArray m_currentDecryptionKey;
    QByteArray m_sessionToken;
    QByteArray m_keySalt;
    QByteArray m_password;
    QByteArray m_buffer;
    bool m_currentDestinationType; //0 - private message, 1 - channel message
    QByteArray m_currentDestination;
    int m_connectionTimeout;
    ConnectionManager(const ConnectionManager&) = delete;
    ConnectionManager& operator=(const ConnectionManager&) = delete;
    QString encryptMessage(const QString &message);
    void processLogIn(QJsonObject responseJSON);
};



#endif // CONNECTIONMANAGER_H
