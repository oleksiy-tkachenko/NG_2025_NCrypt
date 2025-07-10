#ifndef REGISTRATIONDIALOG_H
#define REGISTRATIONDIALOG_H

#include <QDialog>

namespace Ui {
class RegistrationDialog;
}

class RegistrationDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RegistrationDialog(QWidget *parent = nullptr);
    ~RegistrationDialog();
public slots:
    void onServerResponse(const QJsonObject &JSONObject);
    void onReadingError();
private:
    Ui::RegistrationDialog *ui;
    void changeErrorLable(const QString &errorMsg);
private slots:
    void jumpToRegister();
    void jumpToLogIn();
    void jumpToChoicePage();
    void onRegister();
    void onLogIn();
};

#endif // REGISTRATIONDIALOG_H
