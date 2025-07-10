#include "mainwindow.h"

#include <QApplication>
#include <RegistrationDialog.h>
#include <connectionmanager.h>
#include <connectiondialog.h>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    {
        ConnectionDialog connectionDialog;
        if(!connectionDialog.exec()) return 1;
    }
    {
        RegistrationDialog registrationDialog;
        if(!registrationDialog.exec()) return 1;
    }
    MainWindow w;
    w.show();
    return a.exec();
}
