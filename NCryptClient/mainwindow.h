#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "ConnectionManager.h"
#include "conversationcard.h"

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    static QMap<QString, QPixmap> nicknamePictureMap;
    static QPixmap transformIntoProfilePicture(QPixmap &source, int size);
public slots:
    void onDataRecieved(const QJsonObject &response);
    void createConversationCards(const QVector<ConversationInfo> &conversations);
    void onMessageSent(const QByteArray &conversationUUID , const QString &message, qint64 timestamp);
    void onConversationDeleted(const QByteArray &conversationUUID);
    void setDefaultWidget();
signals:
    void pictureReady(const QString &nickname);
private:
    Ui::MainWindow *ui;
    void reSortConversationCards();
    void setPicture(const QJsonObject &response);
    void changePicture();
    void setConversationWidget(const QString &recipientNickname, const QByteArray &uuid,
                               const QByteArray &key, QAESEncryption::Aes keySize,
                               QAESEncryption::Mode keyMode, EncryptionType encryptionType);
    QHash<QByteArray, ConversationCard*> uuidConversationCardHashMap;
    void setPictures(const QJsonObject &response);

    void deleteConversation(const QJsonObject &response);
};
#endif // MAINWINDOW_H
