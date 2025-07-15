#ifndef SERVER_H
#define SERVER_H
#include "QSslSocket"
#include "QSslServer"
#include "databasemanager.h"
#include <QObject>

struct User{
    QSslSocket *socket;
    QString nickname;
    QByteArray sessionToken;
    QByteArray currentChallenge;
};


class Server : public QSslServer
{
    Q_OBJECT
public:
    explicit Server();
    void sendMessage(QString message, QSslSocket* socket);
signals:
private:
    DatabaseManager m_databaseManager = DatabaseManager("NCrypt.db");
    QVector<User> m_users;
    QByteArray m_Data;
    QHash<QSslSocket*, QByteArray> m_socketBufferHash;
    void SendToClient();
    QByteArray m_publicKey, m_privateKey;
    void logInUser(const QJsonObject &requestJSON, QSslSocket* sender);
    void registerUser(const QJsonObject &requestJSON, QSslSocket* sender);
    QByteArray generateRandomBytes(int length);
    QByteArray generateSessionToken();
    QByteArray generateChallenge();
    void checkChallenge(const QJsonObject &requestJSON, QSslSocket *sender);
    User* findUserBySocket(QSslSocket *sender);
    void saveProfilePicture(const QJsonObject &requestJSON, QSslSocket *sender);
    void givePicture(const QJsonObject &requestJSON, QSslSocket *sender);
    void setupSsl();
    bool isSessionTokenCorrect(QByteArray sentSessionToken, User* user);
    void createConversation(const QJsonObject &requestJSON, QSslSocket *sender);
    void completeConversation(const QJsonObject &requestJSON, QSslSocket *sender);
    void giveConversations(const QJsonObject &requestJSON, QSslSocket *sender, bool fetchNew = false);
    void givePictures(const QJsonObject &requestJSON, QSslSocket *sender);
    void giveMessages(const QJsonObject &requestJSON, QSslSocket *sender);
    void processMessage(const QJsonObject &requestJSON, QSslSocket *sender);
    QJsonObject createConversationJSON(const ConversationInfo &conversation);
    bool isRecipientOnline(const QString &recipientNickname, QSslSocket *&recipientSocket);
    void deleteConversation(const QJsonObject &requestJSON, QSslSocket *sender);
public slots:
    void incomingConnection(qintptr socketDescriptor);
    void slotReadyRead();
    void onClientDisconnect();
    void onEncrypted();
};

#endif // SERVER_H
