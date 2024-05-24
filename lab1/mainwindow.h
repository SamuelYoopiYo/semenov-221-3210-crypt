#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QLineEdit>
#include <QJsonArray>
#include <QMainWindow>


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    bool readJSON(unsigned char *key);
    QJsonArray jsonArr;
    void filterListWidget(const QString &searchStrings);
    static int doDecrypt(const QByteArray& encryptedBytes, QByteArray& decryptedBytes, unsigned char *key);
    int doEncrypt(const QByteArray& encryptedBytes, QByteArray& decryptedBytes, unsigned char *key);
    ~MainWindow();

private:
    Ui::MainWindow *ui;

private slots:

    void on_lineEdit_2_returnPressed();
    void on_pushButton_clicked();
    void on_pushButton_2_clicked();
    void on_pushButton_3_clicked();
};
#endif // MAINWINDOW_H
