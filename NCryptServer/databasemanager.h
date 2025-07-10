#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <QSqlDatabase>

class DatabaseManager
{
public:
    DatabaseManager(const QString& path);
    bool userExists(const QString &nickname);
    bool addUser(const QString &nickname, const QByteArray &salt, const QByteArray &publicKey, const QByteArray &privateKey);
    QByteArray getUserValue(const QString &nickname, const QString &valueName);
    bool updatePicture(QByteArray &pictureData, const QString &nickname);
private:
    QSqlDatabase m_database;
};

#endif // DATABASEMANAGER_H
