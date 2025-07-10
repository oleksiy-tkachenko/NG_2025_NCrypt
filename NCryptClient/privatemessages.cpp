#include "privatemessages.h"
#include "ui_privatemessages.h"

PrivateMessages::PrivateMessages(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::PrivateMessages)
{
    ui->setupUi(this);
}

PrivateMessages::~PrivateMessages()
{
    delete ui;
}
