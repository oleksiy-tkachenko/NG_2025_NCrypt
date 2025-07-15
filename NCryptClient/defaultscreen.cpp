#include "defaultscreen.h"
#include "ui_defaultscreen.h"

#include <ConnectionManager.h>

defaultScreen::defaultScreen(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::defaultScreen)
{
    ui->setupUi(this);
    jumpToChoicePage();
    connect(ui->jumpToPMBtn, &QAbstractButton::pressed, this, &defaultScreen::jumpToCreateConversation);
    connect(ui->jumpToCGroupsBtn, &QAbstractButton::pressed, this, &defaultScreen::jumpToCreateGroup);
    connect(ui->jumpToJGroupsBtn, &QAbstractButton::pressed, this, &defaultScreen::jumpToJoinGroup);
    connect(ui->backPMBtn, &QAbstractButton::pressed, this, &defaultScreen::jumpToChoicePage);
    connect(ui->backCGroupBtn, &QAbstractButton::pressed, this, &defaultScreen::jumpToChoicePage);
    connect(ui->backJGroupBtn, &QAbstractButton::pressed, this, &defaultScreen::jumpToChoicePage);
    connect(ui->startConversationBtn, &QAbstractButton::pressed, this, &defaultScreen::onConversationStart);
    connect(ui->createGroupBtn, &QAbstractButton::pressed, this, &defaultScreen::onCreateGroup);
    connect(ui->joinGroupBtn, &QAbstractButton::pressed, this, &defaultScreen::onJoinGroup);
    connect(ui->rsaCheckbox, &QCheckBox::checkStateChanged, this, &defaultScreen::onRSAChecked);
    connect(ConnectionManager::instance(), &ConnectionManager::readingError, this, &defaultScreen::onReadingError);
    connect(ConnectionManager::instance(), &ConnectionManager::dataReceived, this, &defaultScreen::onServerResponse);
}

void defaultScreen::onReadingError()
{
    changeErrorLable("There are issues with a server right now, try again");
}

void defaultScreen::onServerResponse(const QJsonObject &response)
{
    if(response.contains("error_msg")){
        changeErrorLable(response["error_msg"].toString());
        return;
    }
}

void defaultScreen::onRSAChecked(Qt::CheckState checkState)
{
    bool isChecked = checkState;
    ui->aesMode->setEnabled(!isChecked);
    ui->aesSize->setEnabled(!isChecked);
    ui->aesLabel->setEnabled(!isChecked);
    m_encryptionType = !isChecked;
}


void defaultScreen::changeErrorLable(const QString &errorMsg)
{
    QWidget *currentWidget = ui->stackedWidget->currentWidget();
    if (currentWidget == ui->startPrivateMessages){
        ui->errorLabelPM->setText(errorMsg);
    } else if (currentWidget == ui->createGroups) {
        ui->errorLabelCGroup->setText(errorMsg);
    } else if (currentWidget == ui->joinGroups) {
        ui->errorLabelJGroup->setText(errorMsg);
    }
}

void defaultScreen::onConversationStart()
{
    QString nickname = ui->userNicknameLE->text();
    QAESEncryption::Aes aesSize = QAESEncryption::Aes(ui->aesSize->currentIndex());
    QAESEncryption::Mode aesMode = QAESEncryption::Mode((ui->aesMode->currentIndex()+1) % 4);
    ConnectionManager::instance()->startConversation(nickname,  m_encryptionType, aesSize, aesMode);
}

void defaultScreen::onJoinGroup()
{
    return;
}
void defaultScreen::onCreateGroup()
{
    return;
}

void defaultScreen::jumpToCreateConversation()
{
    ui->stackedWidget->setCurrentWidget(ui->startPrivateMessages);
}

void defaultScreen::jumpToCreateGroup()
{
    ui->stackedWidget->setCurrentWidget(ui->createGroups);
}

void defaultScreen::jumpToJoinGroup()
{
    ui->stackedWidget->setCurrentWidget(ui->joinGroups);
}

void defaultScreen::jumpToChoicePage()
{
    ui->stackedWidget->setCurrentWidget(ui->choicePage);
}


defaultScreen::~defaultScreen()
{
    delete ui;
}
