#include "registrationdialog.h"
#include "ui_registrationdialog.h"
#include "QJsonObject"
#include <ConnectionManager.h>

RegistrationDialog::RegistrationDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::RegistrationDialog)
{
    ui->setupUi(this);
    jumpToChoicePage();
    connect(ui->registerBtn, &QAbstractButton::pressed, this, &RegistrationDialog::jumpToRegister);
    connect(ui->logInBtn, &QAbstractButton::pressed, this, &RegistrationDialog::jumpToLogIn);
    connect(ui->backLogBtn, &QAbstractButton::pressed, this, &RegistrationDialog::jumpToChoicePage);
    connect(ui->backRegBtn, &QAbstractButton::pressed, this, &RegistrationDialog::jumpToChoicePage);
    connect(ui->confirmRegistrationBtn, &QAbstractButton::pressed, this, &RegistrationDialog::onRegister);
    connect(ui->confirmLogInBtn, &QAbstractButton::pressed, this, &RegistrationDialog::onLogIn);
    connect(ConnectionManager::instance(), &ConnectionManager::readingError, this, &RegistrationDialog::onReadingError);
    connect(ConnectionManager::instance(), &ConnectionManager::dataReceived, this, &RegistrationDialog::onServerResponse);
}

RegistrationDialog::~RegistrationDialog()
{
    delete ui;
}

void RegistrationDialog::onServerResponse(const QJsonObject &response)
{
    if(response.contains("log_in_error_msg")){
        changeErrorLable(response["log_in_error_msg"].toString());
        ui->confirmLogInBtn->setDisabled(false);
        ui->confirmRegistrationBtn->setDisabled(false);
        return;
    }
    if(response.contains("session_token")) {
        accept();
    }
}

void RegistrationDialog::onReadingError()
{
    changeErrorLable("There are issues with a server right now, try again");
}

void RegistrationDialog::changeErrorLable(const QString &errorMsg)
{
    QWidget *currentWidget = ui->stackedWidget->currentWidget();
    if (currentWidget == ui->logInPage){
        ui->errorLabelLogIn->setText(errorMsg);
    } else if (currentWidget == ui->registrationPage) {
        ui->errorLabelRegistration->setText(errorMsg);
    }
}


void RegistrationDialog::jumpToRegister()
{
    ui->stackedWidget->setCurrentWidget(ui->registrationPage);
}

void RegistrationDialog::jumpToLogIn()
{
    ui->stackedWidget->setCurrentWidget(ui->logInPage);
}

void RegistrationDialog::jumpToChoicePage()
{
    ui->stackedWidget->setCurrentWidget(ui->choicePage);
}

void RegistrationDialog::onRegister()
{
    QString nickname = ui->registrationNickLE->text();
    QString password = ui->registrationPassLE->text();
    if(!(password == ui->registrationPassConfirmLE->text())){
        changeErrorLable("Passwords don't match");
        ui->registrationPassLE->clear();
        ui->registrationPassConfirmLE->clear();
    }
    ui->confirmRegistrationBtn->setDisabled(true);
    ConnectionManager::instance()->sendLogInRequest(nickname, password, true);
}

void RegistrationDialog::onLogIn()
{
    QString nickname = ui->logInNickLE->text();
    QString password = ui->logInPassLE->text();
    ui->confirmLogInBtn->setDisabled(true);
    ConnectionManager::instance()->sendLogInRequest(nickname, password, false);
}
