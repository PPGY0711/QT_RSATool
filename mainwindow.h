#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QComboBox>
#include <QTabWidget>
#include <QTextEdit>
#include <QPushButton>
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    int level = 0;//用于标记第几个密钥对的标志数
    explicit MainWindow(QWidget *parent = 0);
    void saveStr2File(QString str, QString filename);
    QString readFromFile();
    ~MainWindow();

private slots:
    void on_generateKeyBtn_clicked();

    void on_savePublicKeyBtn_clicked();

    void on_savePrivateKeyBtn_clicked();

    void on_loadMessageBtn_clicked();

    void on_encryptMessageBtn_clicked();

    void on_saveEncryptedBtn_clicked();

    void on_loadPrivateKeyBtn_clicked();

    void on_loadPublicKeyBtn_clicked();

    void on_loadEncryptedMessageBtn_clicked();

    void on_DecryptMessageBtn_clicked();

    void on_saveDecryptedMessageBtn_clicked();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
