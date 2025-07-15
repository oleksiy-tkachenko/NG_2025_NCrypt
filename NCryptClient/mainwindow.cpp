#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <ConnectionManager.h>
#include <RegistrationDialog.h>
#include <QJsonObject>
#include <QPainter>
#include <QPainterPath>
#include <QFileDialog>
#include <QBuffer>
#include <QImageReader>
#include <defaultScreen.h>
#include <PrivateMessages.h>
#include <QJsonArray>
#include <ConversationCard.h>
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{

    ui->setupUi(this);

    connect(ConnectionManager::instance(), &ConnectionManager::dataReceived, this, &MainWindow::onDataRecieved);
    connect(ui->profilePictureBtn, &QAbstractButton::pressed, this, &MainWindow::changePicture);
    connect(ConnectionManager::instance(), &ConnectionManager::conversationsParsed, this, &MainWindow::createConversationCards);
    ui->nickname->setText(ConnectionManager::instance()->nickname());
    ConnectionManager::instance()->getPictureData();
    ConnectionManager::instance()->getConversations();
    ui->conversationCardsContainer->setAlignment(Qt::AlignTop);
    ui->mainWidgets->addWidget(new defaultScreen());
}

MainWindow::~MainWindow()
{
    delete ui;
}

QMap<QString, QPixmap> MainWindow::nicknamePictureMap;

void MainWindow::onDataRecieved(const QJsonObject &response)
{
    qDebug() << "got data";
    QString responseType = response["response_type"].toString();
    if(responseType == "picture"){
        setPicture(response);
    } else if (responseType == "conversation_complete"){
        ConnectionManager::instance()->updateConversations();
    } else if (responseType == "pictures"){
        setPictures(response);
    } else if (responseType == "conversation_deleted"){
        deleteConversation(response);
    }
}

void MainWindow::createConversationCards(const QVector<ConversationInfo> &conversations)
{
    QVector<QString> nicknames;
    for(const ConversationInfo &conversation : conversations){
        if(uuidConversationCardHashMap.contains(conversation.uuid)) {
            uuidConversationCardHashMap[conversation.uuid]->setNewLastMessageInfo(conversation.lastMessage,
                                                                                 conversation.lastMessageSender,
                                                                                 conversation.lastMessageTime);
        } else {
            ConversationCard* conversationCard = new ConversationCard(this, conversation.nickname, conversation.key,
                                                                      conversation.uuid, conversation.keySize, conversation.keyMode, conversation.encryptionType,
                                                                      conversation.lastMessage, conversation.lastMessageSender ,conversation.lastMessageTime);
            uuidConversationCardHashMap[conversation.uuid] = conversationCard;
            ui->conversationCardsContainer->addWidget(conversationCard);
            connect(conversationCard, &ConversationCard::pressed, this, &MainWindow::setConversationWidget);
            nicknames.push_back(conversation.nickname);
        }
    }
    reSortConversationCards();
    ConnectionManager::instance()->getPicturesData(nicknames);
}

void MainWindow::onMessageSent(const QByteArray &conversationUUID, const QString &message, qint64 timestamp)
{
    ConversationCard* cardToChange = uuidConversationCardHashMap[conversationUUID];
    cardToChange->setNewLastMessageInfo(message, ConnectionManager::instance()->nickname(), timestamp);
}

void MainWindow::onConversationDeleted(const QByteArray &conversationUUID)
{
    ConversationCard *conversationCard = uuidConversationCardHashMap[conversationUUID];
    ui->conversationCardsContainer->removeWidget(conversationCard);
    conversationCard->deleteLater();
    setDefaultWidget();
    ConnectionManager::instance()->deleteConversation(conversationUUID);
}

void MainWindow::reSortConversationCards() {
    QLayout *cardContainer = ui->conversationCardsContainer;
    int count = cardContainer->count();
    if (count <= 1) return;

    QVector<ConversationCard*> cards;
    QLayoutItem *item;
    while ((item = cardContainer->takeAt(0)) != nullptr) {
        if (ConversationCard *card = (ConversationCard*)item->widget()) {
            cards.append(card);
        }
        delete item;
    }

    std::sort(cards.begin(), cards.end(),
              [](ConversationCard *a, ConversationCard *b) {
                  return a->lastMessageTime() > b->lastMessageTime();
              });

    for (ConversationCard *card : cards) {
        cardContainer->addWidget(card);
    }
}

QPixmap MainWindow::transformIntoProfilePicture(QPixmap &source, int size){
    if(source.isNull()){
        source.load(":/defaultProfilePicture.png");
    }
    QPixmap result(size, size);
    result.fill(Qt::transparent);
    QPainter painter(&result);
    painter.setRenderHint(QPainter::Antialiasing);
    QPainterPath path;
    path.addEllipse(0, 0, size, size);
    painter.setClipPath(path);
    QPixmap scaledPicture = source.scaled(size, size, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
    int x = (scaledPicture.width() - size) / 2;
    int y = (scaledPicture.height() - size) / 2;
    QPixmap croppedPicture = scaledPicture.copy(x, y, size, size);
    painter.drawPixmap(0, 0, croppedPicture);

    return result;
}

void MainWindow::setPicture(const QJsonObject &response)
{
    QPixmap picture;
    if(response["picture"].isNull() || response["picture"].toString().isEmpty()){
        picture.load(":/defaultProfilePicture.png");
    } else {
        QByteArray pictureData = QByteArray::fromBase64(response["picture"].toString().toUtf8());
        picture.loadFromData(pictureData);
    }
    if(!response.contains("nickname")){
        nicknamePictureMap[ui->nickname->text()] = picture;
        picture = transformIntoProfilePicture(picture, ui->profilePictureBtn->height());
        ui->profilePictureBtn->setIconSize(ui->profilePictureBtn->size());
        ui->profilePictureBtn->setIcon(QIcon(picture));
    } else {
        QString nickname = response["nickname"].toString();
        nicknamePictureMap[nickname] = picture;
        emit pictureReady(nickname);
    }
}

// changing picture to 100x100 jpeg for less memory usage in database
void MainWindow::changePicture()
{
    int size = 100;
    QString filePath = QFileDialog::getOpenFileName(this, "Select an Image", "",
                            ("Images (*.png *.jpg *.jpeg *.bmp *.gif *.webp)"));

    if (filePath.isEmpty()) return;
    QImage picture(filePath);
    if (picture.isNull()) return;
    QImage scaledPicture = picture.scaled(size, size, Qt::KeepAspectRatioByExpanding, Qt::SmoothTransformation);
    int x = (scaledPicture.width() - size) / 2;
    int y = (scaledPicture.height() - size) / 2;
    QImage croppedPicture = scaledPicture.copy(x, y, size, size);
    QByteArray pictureData;
    QBuffer buffer(&pictureData);
    buffer.open(QIODevice::ReadWrite);
    croppedPicture.save(&buffer, "JPEG", 100);


    ConnectionManager::instance()->changePicture(pictureData);

}

void MainWindow::setConversationWidget(const QString &recipientNickname, const QByteArray &uuid,
                                       const QByteArray &key, QAESEncryption::Aes keySize,
                                       QAESEncryption::Mode keyMode, EncryptionType encryptionType)
{
    QWidget *currentWidget = ui->mainWidgets->currentWidget();
    ui->mainWidgets->removeWidget(currentWidget);
    currentWidget->deleteLater();
    ConnectionManager::instance()->setCurrentEncryptionType(encryptionType);
    PrivateMessages *nextWidget = new PrivateMessages(this, recipientNickname, uuid, key, keySize, keyMode);
    connect(nextWidget, &PrivateMessages::conversationDeleted, this, &MainWindow::onConversationDeleted);
    ui->mainWidgets->addWidget(nextWidget);
    ui->mainWidgets->setCurrentWidget(nextWidget);
}


void MainWindow::setPictures(const QJsonObject &response)
{
    QJsonArray picturesWithNames = response["pictures"].toArray();
    for(const QJsonValue &value : picturesWithNames){
        if (!value.isObject()) continue;
        QJsonObject pictureWithName = value.toObject();
        QString nickname = pictureWithName["nickname"].toString();
        QByteArray pictureData = QByteArray::fromBase64(pictureWithName["picture"].toString().toUtf8());
        QPixmap picture;
        picture.loadFromData(pictureData);
        nicknamePictureMap[nickname] = picture;
        emit pictureReady(nickname);
    }
}

void MainWindow::setDefaultWidget()
{
    QWidget *currentWidget = ui->mainWidgets->currentWidget();
    ui->mainWidgets->removeWidget(currentWidget);
    currentWidget->deleteLater();
    defaultScreen *nextWidget = new defaultScreen(this);
    ui->mainWidgets->addWidget(nextWidget);
    ui->mainWidgets->setCurrentWidget(nextWidget);
}

void MainWindow::deleteConversation(const QJsonObject &response)
{
    QByteArray conversationUUID = QByteArray::fromBase64(response["conversation_uuid"].toString().toUtf8());
    ConversationCard *conversationCard = uuidConversationCardHashMap[conversationUUID];
    ui->conversationCardsContainer->removeWidget(conversationCard);
    conversationCard->hide();
    conversationCard->setParent(nullptr);
    conversationCard->deleteLater();
    uuidConversationCardHashMap.remove(conversationUUID);
    PrivateMessages *currentWidget = qobject_cast<PrivateMessages*>(ui->mainWidgets->currentWidget());
    if (currentWidget != nullptr && currentWidget->uuid() == conversationUUID) {
        setDefaultWidget();
    }
}

