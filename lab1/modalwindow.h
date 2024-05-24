#ifndef MODALWINDOW_H
#define MODALWINDOW_H

#include <QDialog>

namespace Ui {
class ModalWindow;
}

class ModalWindow : public QDialog
{
    Q_OBJECT

public:
    explicit ModalWindow(QWidget *parent = nullptr);
    static QString getPin(QWidget *parent = nullptr);
    ~ModalWindow();

private slots:
    void on_passwordLineEdit_returnPressed();

private:
    Ui::ModalWindow *ui;

signals:
  void sendData(QString pin);
};

#endif // MODALWINDOW_H
