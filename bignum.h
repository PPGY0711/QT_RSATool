#ifndef BIGNUM_H
#define BIGNUM_H
#include <QtGlobal>
#include <QString>
#include <QFile>
#include <QTextStream>
#include <QTextCodec>
#include <QChar>
#include <QDebug>
#include <ctime>
#include <memory.h>
#include <iostream>
using namespace std;

//bignum的数据结构定义
#define BITPERBLOCK     32              //定义一个数由若干个block组成，每个block是32位的无符号整数
#define BNMAXBLOCK      256             //定义BN的最大block数，即最多可以表示一个32*BITPERBLOCK位的无符号整数（表示的方式为每32位一个截断）且使用小端存储
//这个BNMAXBLOCK一直从32扩展到比64位还要大，原因是在knuth除法在block数小的时候容易数组越界产生段错误
#define BNMAXBIT        BNMAXBLOCK<<5   //BN的实际最大的二进制位数，1024
typedef quint32         BN[BNMAXBLOCK + 1];  //BN使用无符号32位整数的数组存储，第[0]位存储BN的block数，可以为是BN的block长度
#define BNDMAXBLOCK     BNMAXBLOCK<<1   //BND最大的block数为BN的两倍
#define BNDMAXBIT       BNMAXBIT<<1     //BND为扩展长度的BN，可以表示2048位的无符号整数
typedef quint32         BND[(BNMAXBLOCK << 1) + 1]; //BND同样使用无符号32位整数的数组存储
#define MAXU32L          0xffffffffUL
#define MAXU32LL         0xffffffffULL
#define TWOPOW31U       0x80000000UL
#define TWOPOW32U       0x100000000ULL
#define BNSIZE          sizeof(BN)
typedef quint32*        BNPTR;
//bignum的简单宏函数定义
//1.比较大小
#define MIN(a,b)            ((a)<(b)?(a):(b))
//2.获得block数，bn[0]里存的是uint32位整数的个数
#define GETBLOCKNUM(bn)     ((quint32)*(bn))
//3.设置block数，即改变bn[0]
#define SETBLOCKNUM(bn,n)   (*(bn) = (quint32)(n))
//4.获取bn最高位分割得到的无符号32位整数所在block的索引
#define PTRTOMSDBLOCK(bn)   ((bn)+GETBLOCKNUM(bn))
//5.获取bn最低位分割得到的无符号32位整数所在block的索引
#define PTRTOLSDBLOCK(bn)   ((bn)+1)
//6.设置一个BN为0,即将bn的block数置为0
#define SETZERO(bn)         (*(bn) = 0)


//使用inline定义的bignum频繁调用简单函数
//1.block数加1
inline void INCBLOCKNUM(BN bn){
    *(bn) = *(bn) + 1;
}
//2.block数减1
inline void DECBLOCKNUM(BN bn){
    if(*(bn) > 0){
        *(bn) = *(bn) - 1;
    }
}
//3.消除全为0的block，相当于消除大数中的前置0
inline void DELFRONTZEROS(BN bn){
    while((*PTRTOMSDBLOCK(bn) == 0) && (GETBLOCKNUM(bn) > 0)){
        DECBLOCKNUM(bn);
//        *(bn) = *(bn) - 1;
    }
}
//4.复制大数
inline void CPYBN(BN dest, BN src){
    memset(dest,0,BNSIZE);
    DELFRONTZEROS(src);
    quint32 *high = PTRTOMSDBLOCK(src);
    quint32 *cur, blockNum = GETBLOCKNUM(src);
    if(blockNum == 0U){
        SETZERO(dest);
        return;
    }
    cur = dest + blockNum;
    while(high > src){
        *cur = *high;
        high--;
        cur--;
    }
    SETBLOCKNUM(dest,blockNum);
}
//5.将一个uint32包装成BN形式
inline void GENBNFROMU32(BN num, quint32 u){
    memset(num,0,BNSIZE);
    *(PTRTOLSDBLOCK(num)) = u;
    SETBLOCKNUM(num,1);
    DELFRONTZEROS(num); //包含u为0的情况
}
//6.比较两个BN的大小(1:a>b;0:a=b;-1:a<b)
inline int COMPARE(BN a, BN b){
    DELFRONTZEROS(a);
    DELFRONTZEROS(b);
    quint32 *maptr = PTRTOMSDBLOCK(a),*mbptr = PTRTOMSDBLOCK(b);
    int lenA = (int)GETBLOCKNUM(a), lenB = (int)GETBLOCKNUM(b);
    if(lenA == 0 && lenB == 0) return 0;
    if(lenA > lenB) return 1;
    if(lenA < lenB) return -1;
    while(((*maptr) == (*mbptr)) && (maptr > a)){
        maptr--;
        mbptr--;
    }
    if(maptr == a) return 0; //a和b到最后一个block都相等，则两个数相等
    if((*maptr) > (*mbptr)) return 1;   //在其中某一blocka比b大，则a比b大
    else return -1;
}
//7.得到最大的1024位无符号整数（每一个block都设置成全1
inline void SETMAXBN(BN a){
    quint32 *aptr = a, *maptr = a + BNMAXBLOCK;
    while((++aptr) <= maptr){
        *aptr = MAXU32L;
    }
    SETBLOCKNUM(a,BNMAXBLOCK);
}

//bignum的各类运算
//加法运算
void _add(BN a, BN b, BN res);              //内部实际加法过程
void add_in_BN(BN a, BN b, BN res);         //结果超过BN最大二进制位数截断加法
void add_out_BN(BN a, BN b, BN res);        //结果超过BN最大二进制位数不截断加法
void add_u32(BN a, quint32 b, BN res);      //BN加上一个uint32
//减法运算
void _sub(BN a, BN b, BN res);              //内部实际减法过程，直接相减
void sub_in_BN(BN a, BN b, BN res);         //结果可以用补码表示的减法
void sub_u32(BN a, quint32 b, BN res);      //减去一个uint32
//乘法运算
void mul_in_BN(BN a, BN b, BN res);         //保留BN最大二进制位数结果的乘法
void _mul(BN a, BN b, BN res);              //内部乘法实际过程，结果可能超过BN最大位数
//位运算操作
quint32 get_bin_bits(BN a);                 //获取BN的二进制位数
void _shift_left(BN a);                     //左移一位（位数最多扩展到2*BN的最大BIT位）
void shift_left_in_BN(BN a);                //总二进制控制的左移，超过最大位数为0
void shift_right(BN a);                     //右移一位
//除法操作
void slow_div(BN a, BN b, BN quo, BN rem);  //移位除法，结果可靠但速度较慢
void knuth_div(BN a, BN b, BN quo, BN rem); //根据Knuth猜商法实现的快速除法
//取模操作，内部调用knuth的估商大数除法
void mod(BN a, BN n, BN rem);               //求 a mod n
void mod_add(BN a, BN b, BN n, BN rem);     //求 (a+b)mod n
void mod_sub(BN a, BN b, BN n, BN rem);     //求 (a-b)mod n
void mod_mul(BN a, BN b, BN n, BN rem);     //求 (a*b)mod n
//蒙哥马利算法函数(在模数n为偶数时失效，另外还有错误）
void mont_red_prepare(BN n, BN t0);			//蒙哥马利约减的准备函数，计算逆元
void mont_red(BN a, BN b, BN n, BN t, BN rem);//蒙哥马利约简
void mont_mul(BN a, BN b, BN n, BN rem);    //蒙哥马利模乘
void mont_exp(BN base, BN exp, BN n, BN rem); //蒙哥马利模幂
//数论相关简单函数
quint32 gcd(BN a, BN b, BN res);            //欧几里得算法求最大公因数，返回求解步数
void stein_gcd(BN a, BN b, BN res);         //化归方法移位求最大公因数
void inv(BN a, BN n, BN res);               //求使得ax mod n = 1 的x,(a,n)=1
//素数生成相关函数
bool fermat_test(BN p);                     //费马检测
bool miller_test(BN p, int test_time = 3);  //miller-rabin检测（默认检测次数为3）
void gen_rand(BN ran, quint32 bits);        //产生随机的bits位BN
void gen_prime_aid();                       //辅助函数用于计算小素数的乘积
void gen_prime_slow(int bits);              //产生两个bits位的素数作为辅助函数生成安全大素数p，q（速度较慢不能保证在1s内，所以是提前算好的），bits一般取512,768,1024
void gen_prime(BN p,int bits);              //产生一个bits位的素数版本1
void gen_prime_chen(BN p, int bits);        //产生一个bits位的素数版本2，用陈氏定理
void gen_safe_prime(BN p, int bits);        //产生bits位的安全大素数p
//字符串及文件处理函数(16进制处理且不带0x前缀）
void printBN(BN n);                         //打印BN
QString bn2str(BN bn);                      //将BN转换成16进制数的字符串
void str2bn(BN bn, QString num_str);        //将16进制字符串转换成BN
void write_bn_to_file(BN b, QString file);  //将bn写到文件
void read_bn_from_file(BN b, QString file); //从文件读bn
//rsa加解密相关
void genpq_safe(BN p, BN q, int bits);      //产生bits位的安全大素数p,q，较慢
void genpq_unsafe(BN p, BN q, int bits);    //产生bits位的大素数p、q（不一定满足安全要求）,更快
quint32** initial_keys(int key_type);       //初始化密钥数组
BNPTR** gen_key(int bits);                  //生成位数为bits的密钥数组，包括公私钥
void _gen_key(quint32** pb_key, quint32** pr_key, int bits);//生成公钥和私钥,bits表示密钥的级别(512/768/1024)
//加解密
QString encrpyt_message(QString msg, BN e, BN n, int bits);//加密，字符串默认中英文可夹杂，转成Unicode字符串之后划分加密（明文长度以字节数为单位）
QString decrypt_message(QString cipher, BN d, BN n, int bits);//解密

#endif // BIGNUM_H
