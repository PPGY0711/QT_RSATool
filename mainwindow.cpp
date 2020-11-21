#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "bignum.h"
#include <iostream>
#include <QFileDialog>
#include <QMessageBox>
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    //具体要不要实施只读要看，这个属于交互了
//    ui->valueAEdit->setReadOnly(true);
//    ui->valueBEdit->setReadOnly(true);
//    ui->valueNEdit->setReadOnly(true);
//    ui->valuePEdit->setReadOnly(true);
//    ui->valueQEdit->setReadOnly(true);
//    ui->messageEdit->setReadOnly(true);
//    ui->encryptedMessageEdit->setReadOnly(true);
//    ui->valueAEdit2->setReadOnly(true);
//    ui->valueBEdit2->setReadOnly(true);
//    ui->valueNEdit2->setReadOnly(true);

    //    QLabel *normal=new QLabel("正常信息",this);
    //    ui->statusBar->addWidget(normal);//显示正常信息

    ui->statusBar->setSizeGripEnabled(false);//去掉状态栏右下角的三角
    QLabel *permanent=new QLabel(this);
    permanent->setFrameStyle(QFrame::Box|QFrame::Sunken);
    permanent->setText(tr("<a href=\"https://github.com/PPGY0711/QT_RSATool\">For More Information</a>"));
    permanent->setOpenExternalLinks(true);//设置可以打开网站链接
    ui->statusBar->addPermanentWidget(permanent);//显示永久信息
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_generateKeyBtn_clicked()
{
    QComboBox* box = ui->dropMenu;
    int index = box->currentIndex();
    int choice[3] = {1024,768,512};
    int bits = choice[index];
    //先清空原来的
    QTextEdit* valueN = ui->valueNEdit;
    QTextEdit* valueB = ui->valueBEdit;
    QTextEdit* valueA = ui->valueAEdit;
    QTextEdit* valueP = ui->valuePEdit;
    QTextEdit* valueQ = ui->valueQEdit;
    valueN->clear();
    valueA->clear();
    valueB->clear();
    valueP->clear();
    valueQ->clear();
    clock_t start = clock();
    BNPTR** keys = gen_key(bits);
    clock_t end = clock();
    QString cost = "Generate " + QString::number(bits,10) + " keys cost: " + QString::number(end-start) + " ms.";
    ui->statusBar->showMessage(cost,5000);
    quint32 **pb_keys,**pr_keys;
    pb_keys = keys[0];//n,e
    pr_keys = keys[1];//p,q,d,fai_n
    //设置新的密钥
    valueN->setPlainText(bn2str(pb_keys[0]));
    valueB->setPlainText(bn2str(pb_keys[1]));
    valueA->setPlainText(bn2str(pr_keys[2]));
    valueP->setPlainText(bn2str(pr_keys[0]));
    valueQ->setPlainText(bn2str(pr_keys[1]));
    MainWindow::level = bits;
}

void MainWindow::on_savePublicKeyBtn_clicked()
{
    //保存公钥
    QComboBox* box = ui->dropMenu;
//    qDebug() << box->currentText() << " " << box->currentIndex() << endl;
    int index = box->currentIndex();
    int choice[3] = {1024,768,512};
    int bits = choice[index];
    QString str;
    str.append("------Value N:\n");
    QTextEdit* valueN = ui->valueNEdit;
    str.append(valueN->toPlainText());
    str.append("\n");
    str.append("------Value B:\n");
    QTextEdit* valueB = ui->valueBEdit;
    str.append(valueB->toPlainText());
    str.append("\n");
    saveStr2File(str,"publicKey_"+QString::number(bits,10) +".txt");
}

void MainWindow::on_savePrivateKeyBtn_clicked()
{
    //保存私钥
    QComboBox* box = ui->dropMenu;
//    qDebug() << box->currentText() << " " << box->currentIndex() << endl;
    int index = box->currentIndex();
    int choice[3] = {1024,768,512};
    int bits = choice[index];
    QString str;
    str.append("------Value A:\n");
    QTextEdit* valueA = ui->valueAEdit;
    str.append(valueA->toPlainText());
    str.append("\n");
    str.append("------Value P:\n");
    QTextEdit* valueP = ui->valuePEdit;
    str.append(valueP->toPlainText());
    str.append("\n");
    str.append("------Value Q:\n");
    QTextEdit* valueQ = ui->valueQEdit;
    str.append(valueQ->toPlainText());
    str.append("\n");
    saveStr2File(str,"privateKey_"+QString::number(bits,10) +".txt");
//    MainWindow::keypair_count++;
}

void MainWindow::on_loadMessageBtn_clicked()
{
    //读取.txt文本文件
    QString str = "";
    str = readFromFile();
//    qDebug() << str << endl;
    QTextEdit* msgEdit = ui->messageEdit;
    msgEdit->clear();
    msgEdit->setPlainText(str.toStdString().data());
}

void MainWindow::on_encryptMessageBtn_clicked()
{
    //加密文本并输出
    QString str,Bstr,Nstr;
    QTextEdit* msgEdit = ui->messageEdit;
    str = msgEdit->toPlainText();
    QTextEdit* valueB = ui->valueBEdit;
    QTextEdit* valueN = ui->valueNEdit;
    Bstr = valueB->toPlainText();
    Nstr = valueN->toPlainText();
    BN b,n;
    str2bn(b,Bstr);
    str2bn(n,Nstr);
    QString text = encrpyt_message(str,b,n,MainWindow::level);
    QTextEdit* enMsgEdit = ui->encryptedMessageEdit;
    enMsgEdit->clear();
    enMsgEdit->setPlainText(text);

}

void MainWindow::on_saveEncryptedBtn_clicked()
{
    //保存加密文件
    QComboBox* box = ui->dropMenu;
//    qDebug() << box->currentText() << " " << box->currentIndex() << endl;
    int index = box->currentIndex();
    int choice[3] = {1024,768,512};
    int bits = choice[index];
    QTextEdit* enMsgEdit = ui->encryptedMessageEdit;
    QString str = enMsgEdit->toPlainText();
    str.append("\n");
    saveStr2File(str,"encryptedMsg_"+QString::number(bits,10) +".txt");
}

void MainWindow::on_loadPrivateKeyBtn_clicked()
{
    //读取私钥文件
    QString str = "";
    str = readFromFile();
    //读取A
    QStringList strList = str.split("\n");
    QString Astr = strList.at(1);
    QTextEdit* valueA = ui->valueAEdit2;
    valueA->clear();
    valueA->setPlainText(Astr.toStdString().data());
}

void MainWindow::on_loadPublicKeyBtn_clicked()
{
    //读取公钥文件
    QString str = "";
    str = readFromFile();
    //读取N，B
    QStringList strList = str.split("\n");
    QString Bstr,Nstr;
    Nstr = strList.at(1);
    Bstr = strList.at(3);
    QTextEdit* valueN = ui->valueNEdit2;
    valueN->clear();
    valueN->setPlainText(Nstr.toStdString().data());
    QTextEdit* valueB = ui->valueBEdit2;
    valueB->clear();
    valueB->setPlainText(Bstr.toStdString().data());
}

void MainWindow::on_loadEncryptedMessageBtn_clicked()
{
    //读取加密.txt文本文件
    QString str = "";
    str = readFromFile();
//    qDebug() << str << endl;
    QTextEdit* enMsgEdit = ui->encryptedMessageEdit2;
    enMsgEdit->clear();
    enMsgEdit->setPlainText(str.toStdString().data());
}

void MainWindow::on_DecryptMessageBtn_clicked()
{
    //解密文本并输出
    QString str,Astr,Nstr;
    QTextEdit* enMsgEdit = ui->encryptedMessageEdit2;
    str = enMsgEdit->toPlainText().remove("\n");
    QTextEdit* valueA = ui->valueAEdit2;
    QTextEdit* valueN = ui->valueNEdit2;
    Astr = valueA->toPlainText();
    Nstr = valueN->toPlainText();
    BN a,n;
    str2bn(a,Astr);
    str2bn(n,Nstr);
    QString text = decrypt_message(str,a,n,MainWindow::level);
    QTextEdit* msgEdit = ui->messageEdit2;
    msgEdit->clear();
    msgEdit->setPlainText(text);
}

void MainWindow::on_saveDecryptedMessageBtn_clicked()
{
    //保存解密文件
    QTextEdit* deMsgEdit = ui->messageEdit2;
    QString str = deMsgEdit->toPlainText();
    str.append("\n");
    saveStr2File(str,"decryptedMsg.txt");
}

void MainWindow::saveStr2File(QString str, QString filename){
    QFileDialog fileDialog;
    QString filename2 = fileDialog.getSaveFileName(this,"Open File",filename,"Text File(*.txt)");
    if(filename2 == ""){
        return;
    }
    QFile file(filename2);
    if(!file.open(QIODevice::WriteOnly | QIODevice::Truncate)){
        QMessageBox::warning(this,"error","Open file failure!");
        return;
    }
    else{
        QTextStream out(&file);
        out << str;
        QMessageBox::warning(this,"tip","Save File Success!");
        file.close();
    }
}

QString MainWindow::readFromFile(){

    QString fileName,content;
    fileName = QFileDialog::getOpenFileName(this,"Open File","","Text File(*.txt)");
    if(fileName == "")
    {
        return "";
    }
    else
    {
        QFile file(fileName);
        if(!file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            QMessageBox::warning(this,"error","open file error!");
            return "";
        }
        else
        {
            if(!file.isReadable())
                QMessageBox::warning(this,"error","this file is not readable!");
            else
            {
                QTextStream textStream(&file);
                while(!textStream.atEnd())
                {
                    content = textStream.readAll();
                    qDebug() << "read from file: "<< content << endl;
                }
                file.close();
            }
        }
    }
    return content;
}
