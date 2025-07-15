#include "connectiondialog.h"
#include "ui_connectiondialog.h"

#include <ConnectionManager.h>



ConnectionDialog::ConnectionDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::ConnectionDialog)
{
    ui->setupUi(this);
    ConnectionManager::instance();
    m_closingTimer = new QTimer(this); // to read the connection message
    m_closingTimer->setSingleShot(true);
    m_reconnectionTimer = new QTimer(this);
    m_reconnectionTimer->setSingleShot(true);
    connect(m_closingTimer, &QTimer::timeout, this, &ConnectionDialog::accept);
    connect(m_reconnectionTimer, &QTimer::timeout, this, &ConnectionDialog::onReconnect);

    connect(ui->cancelButton, &QAbstractButton::pressed, this, &ConnectionDialog::onCancel);

    connect(ConnectionManager::instance(), &ConnectionManager::connectionTimeout, this, &ConnectionDialog::onTimeout);
    connect(ConnectionManager::instance(), &ConnectionManager::connected, this, &ConnectionDialog::onConnected);



}

void ConnectionDialog::onCancel(){
    ConnectionManager::instance()->disconnectFromServer();
    reject();
}

void ConnectionDialog::onConnected(){
    ui->connectionLabel->setText("Connected! Redirecting to registration page!");
    m_closingTimer->start(1000);
}

void ConnectionDialog::onTimeout(){
    ui->connectionLabel->setText("Couldn't connect to the server... Reconnecting in "
                                 + QString::number(m_reconnectionInterval/1000) + " seconds");
    m_reconnectionTimer->start(m_reconnectionInterval);
    m_reconnectionInterval += 1000;
}

void ConnectionDialog::onReconnect(){
    ConnectionManager::instance()->connectToServer();
    ui->connectionLabel->setText("Connecting...");
}

ConnectionDialog::~ConnectionDialog()
{
    delete ui;
}
