#include "listitem.h"
#include "ui_listitem.h"
#include "mainwindow.h"

#include <openssl/evp.h>

#include <QBuffer>
#include <QCryptographicHash>
#include <QFile>
#include <QJsonDocument>
#include <QClipboard>
#include <QMessageBox>

ListItem::ListItem(QString site, QString login_encrypted, QString password_encrypted, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::ListItem)
{
    this->pass_encr = new char[password_encrypted.length()];
    QByteArray pass_ba = password_encrypted.toUtf8();
    strcpy(pass_encr, pass_ba.data());
    qDebug() << "***pass_encr" << pass_encr;

    this->log_encr = new char[login_encrypted.length()];
    QByteArray log_ba = login_encrypted.toUtf8();
    strcpy(log_encr, log_ba.data());
    qDebug() << "***log_encr" << log_encr;

    ui->setupUi(this);

    ui->url->setText(site);
    ui->loginLineEdit->setText("******");
    ui->passwordLineEdit->setText("******");

    QPixmap pix(":/img/img/keys.png");
    int w = ui->icon->width();
    int h = ui->icon->height();

    ui->icon->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
}

bool ListItem::checkJSON(unsigned char *key)
{
    QFile jsonFile("/home/ezhik/pars/json/cridentials_encrypted.json");
    if(!jsonFile.open(QIODevice::ReadOnly)) return false;

    QByteArray hexEncryptedBytes = jsonFile.readAll();
    QByteArray encryptedBytes = QByteArray::fromHex(hexEncryptedBytes);
    QByteArray decryptedBytes;

    int ret_code = MainWindow::doDecrypt(encryptedBytes, decryptedBytes, key);

    QJsonDocument jsonDoc = QJsonDocument::fromJson(decryptedBytes);

    if (!jsonDoc.isObject())
    {
        return 1;
    }

    jsonFile.close();
    return ret_code;
}

ListItem::~ListItem()
{
    delete [] pass_encr;
    delete ui;
}


void ListItem::on_loginCopyPushButton_clicked()
{
    QString pin = ModalWindow::getPin();

    QByteArray hash = QCryptographicHash::hash(pin.toUtf8(), QCryptographicHash::Sha256);

    qDebug() << "***Hash -> " << hash;


    unsigned char hash_key[32] = {0};
    memcpy(hash_key, hash.data(), 32);
    qDebug() << "***hash_key -> " << hash_key;

    if (checkJSON(hash_key) == 0)
    {
        QByteArray hexEncryptedLog(log_encr);
        QByteArray encryptedLog = QByteArray::fromHex(hexEncryptedLog);
        QByteArray decryptedLog;

        if (MainWindow::doDecrypt(encryptedLog, decryptedLog, hash_key) == 0)
        {
            QString login(decryptedLog);
            QClipboard *clipboard = QGuiApplication::clipboard();
            clipboard->setText(login);
            QMessageBox::about(this, " ", "ЛОГИН СКОПИРОВАН В БУФЕР ОБМЕНА");
        }

        else
        {
            ui->loginLineEdit->setText("Eror");
        }

    }

    else if (pin != "")
    {
        QMessageBox::critical(this, " ", "НЕВЕРНЫЙ ПИН");
    }


}


void ListItem::on_passwordCopyPushButton_clicked()
{
    QString pin = ModalWindow::getPin();

    QByteArray hash = QCryptographicHash::hash(pin.toUtf8(), QCryptographicHash::Sha256);

    qDebug() << "***Hash -> " << hash;


    unsigned char hash_key[32] = {0};
    memcpy(hash_key, hash.data(), 32);
    qDebug() << "***hash_key -> " << hash_key;

    if (checkJSON(hash_key) == 0)
    {
        QByteArray hexEncryptedPass(pass_encr);
        QByteArray encryptedPass = QByteArray::fromHex(hexEncryptedPass);
        QByteArray decryptedPass;

        if (MainWindow::doDecrypt(encryptedPass, decryptedPass, hash_key) == 0)
        {
            QString password(decryptedPass);
            QClipboard *clipboard = QGuiApplication::clipboard();
            clipboard->setText(password);
            QMessageBox::about(this, " ", "ПАРОЛЬ СКОПИРОВАН В БУФЕР ОБМЕНА");
        }

        else
        {
            ui->passwordLineEdit->setText("Eror");
        }

        return;

    }

    else if (pin != "")
    {
        QMessageBox::critical(this, " ", "НЕВЕРНЫЙ ПИН");
    }
}

