#ifndef MESSAGECARD_H
#define MESSAGECARD_H

#include <QFrame>

namespace Ui {
class messageCard;
}

class messageCard : public QFrame
{
    Q_OBJECT

public:
    explicit messageCard(QWidget *parent, const QString &message, const QString &sender, qint64 timestamp);
    ~messageCard();

private:
    Ui::messageCard *ui;
};

#endif // MESSAGECARD_H
