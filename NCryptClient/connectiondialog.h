#ifndef CONNECTIONDIALOG_H
#define CONNECTIONDIALOG_H

#include <QDialog>
#include <QTimer>

namespace Ui {
class ConnectionDialog;
}

class ConnectionDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ConnectionDialog(QWidget *parent = nullptr);
    ~ConnectionDialog();
public slots:
    void onConnected();
    void onTimeout();
    void onReconnect();
    void onCancel();
private:

    Ui::ConnectionDialog *ui;
    uint64_t m_reconnectionInterval = 2000; // 2 seconds
    QTimer *m_closingTimer;
    QTimer *m_reconnectionTimer;
};

#endif // CONNECTIONDIALOG_H
