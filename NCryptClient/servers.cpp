#include "servers.h"
#include "ui_servers.h"

Servers::Servers(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Servers)
{
    ui->setupUi(this);
}

Servers::~Servers()
{
    delete ui;
}
