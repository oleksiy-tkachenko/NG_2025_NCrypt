#ifndef DEFAULTSCREEN_H
#define DEFAULTSCREEN_H

#include <QJsonObject>
#include <QWidget>

namespace Ui {
class defaultScreen;
}

class defaultScreen : public QWidget
{
    Q_OBJECT

public:
    explicit defaultScreen(QWidget *parent = nullptr);
    ~defaultScreen();

private:
    Ui::defaultScreen *ui;
    void jumpToChoicePage();
    void jumpToJoinGroup();
    void jumpToCreateGroup();
    void jumpToCreateConversation();
    void changeErrorLable(const QString &errorMsg);
    int m_encryptionType = 1;
private slots:
    void onConversationStart();
    void onCreateGroup();
    void onJoinGroup();
    void onReadingError();
    void onServerResponse(const QJsonObject &response);
    void onRSAChecked(Qt::CheckState checkState);
};

#endif // DEFAULTSCREEN_H
