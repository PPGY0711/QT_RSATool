#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.setWindowTitle("RSA加解密小工具 by pgy20@mails.tsinghua.edu.cn");
    w.show();

    return a.exec();
}
