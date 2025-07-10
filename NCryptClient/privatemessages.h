#ifndef PRIVATEMESSAGES_H
#define PRIVATEMESSAGES_H

#include <QWidget>

namespace Ui {
class PrivateMessages;
}

class PrivateMessages : public QWidget
{
    Q_OBJECT

public:
    explicit PrivateMessages(QWidget *parent = nullptr);
    ~PrivateMessages();

private:
    Ui::PrivateMessages *ui;
};

#endif // PRIVATEMESSAGES_H
