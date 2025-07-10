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
    QString createTable =
        "CREATE TABLE IF NOT EXISTS users ("
        "nickname TEXT PRIMARY KEY,"
        "salt BLOB,"
        "private_key BLOB,"
        "public_key BLOB,"
        "picture BLOB);";
    if (!query.exec(createTable)) {
        qDebug() << "Create table failed:" << query.lastError();
    }
}

bool DatabaseManager::addUser(const QString& nickname, const QByteArray &salt, const QByteArray &publicKey, const QByteArray &privateKey)
{
    bool success = false;
    // you should check if args are ok first...
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
    query.prepare("SELECT nickname FROM users WHERE nickname = :nickname");
    query.bindValue(":nickname", nickname);

    if (query.exec())
    {
        if (query.next())
        {
            return true;
        }
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

bool DatabaseManager::updatePicture(QByteArray &pictureData, const QString &nickname)
{
    QBuffer buffer(&pictureData);
    buffer.open(QIODevice::ReadOnly);

    QImageReader reader(&buffer);

    if (!reader.canRead()) {
        return false;
    }
    QImage img = reader.read();
    if (img.isNull() || img.width() != 100 || img.height() != 100 ||
        (reader.format().toLower() != "jpeg" && reader.format().toLower() != "jpg")) {
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
