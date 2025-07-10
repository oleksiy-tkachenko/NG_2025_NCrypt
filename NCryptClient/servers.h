#ifndef SERVERS_H
#define SERVERS_H

#include <QWidget>

namespace Ui {
class Servers;
}

class Servers : public QWidget
{
    Q_OBJECT

public:
    explicit Servers(QWidget *parent = nullptr);
    ~Servers();

private:
    Ui::Servers *ui;
};

#endif // SERVERS_H
