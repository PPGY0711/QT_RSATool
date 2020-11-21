#include "bignum.h"

BN ZERO = { 0 };
BN ONE = { 1,1 };
BN TWO = { 1,2 };

//for test
void printBN(BN n) {
    qDebug() << ("bn :================\n");
    for (int i = 1; i <= (int)GETBLOCKNUM(n); i++)
        qDebug() << "bn[ " << i << "]: " << n[i] << endl;
}

void _add(BN a, BN b, BN res)
{
    //    int overflow = 0;
    //内部实际加法过程
    BN tmp_res;
    memset(tmp_res, 0, BNSIZE);
    quint32 *aptr, *bptr, *maptr, *mbptr, *rptr = PTRTOLSDBLOCK(tmp_res);
    quint64 carry = 0ULL;
    //让a指向长度更长的BN
    if (GETBLOCKNUM(a) < GETBLOCKNUM(b)) {
        aptr = PTRTOLSDBLOCK(b);
        maptr = PTRTOMSDBLOCK(b);
        bptr = PTRTOLSDBLOCK(a);
        mbptr = PTRTOMSDBLOCK(a);
        SETBLOCKNUM(tmp_res, GETBLOCKNUM(b));
    }
    else {
        aptr = PTRTOLSDBLOCK(a);
        maptr = PTRTOMSDBLOCK(a);
        bptr = PTRTOLSDBLOCK(b);
        mbptr = PTRTOMSDBLOCK(b);
        SETBLOCKNUM(tmp_res, GETBLOCKNUM(a));
    }
    while (bptr <= mbptr) {
        carry = (quint64)((quint64)(*aptr) + (quint64)(*bptr) + (quint64)(quint32)(carry >> BITPERBLOCK));
        *rptr = (quint32)carry;
        aptr++; bptr++; rptr++;
    }
    while (aptr <= maptr) {
        carry = (quint64)((quint64)(*aptr) + (quint64)(quint32)(carry >> BITPERBLOCK));
        *rptr = (quint32)carry;
        aptr++; rptr++;
    }
    if (carry&TWOPOW32U) {
        *rptr = 1U;
        INCBLOCKNUM(tmp_res);
    }
    CPYBN(res, tmp_res);
}

void add_in_BN(BN a, BN b, BN res) {
    //结果超过BN最大二进制位数截断加法
    _add(a, b, res);
    if (GETBLOCKNUM(res) > (quint32)BNMAXBLOCK) {
        SETBLOCKNUM(res, BNMAXBLOCK);
        DELFRONTZEROS(res);
    }
}

void add_out_BN(BN a, BN b, BN res) {
    //结果超过BN最大二进制位数不截断加法
    _add(a, b, res);
    DELFRONTZEROS(res);
}

void add_u32(BN a, quint32 b, BN res) {
    //BN加上一个uint32
    BN bn;
    GENBNFROMU32(bn, b);
    add_in_BN(a, bn, res);
}

void _sub(BN a, BN b, BN res) {
    //内部实际减法过程，直接相减，结果会保留到最长的block数
    BN tmp_res;
    memset(tmp_res, 0, BNSIZE);
    quint32 *aptr, *bptr, *rptr, *maptr, *mbptr;
    quint64 carry = 0ULL;
    aptr = PTRTOLSDBLOCK(a);
    bptr = PTRTOLSDBLOCK(b);
    maptr = PTRTOMSDBLOCK(a);
    mbptr = PTRTOMSDBLOCK(b);
    rptr = PTRTOLSDBLOCK(tmp_res);
    SETBLOCKNUM(tmp_res, GETBLOCKNUM(a));
    //如果ai<bi，carry的高位会全为1而不是0，判断第33位
    //例如2位二进制，基数为4的情况，carry是4位；01-1则caryy=1110;10-11=1111。判断借位的时候，判断33位二进制位是否为0就可以
    while (bptr <= mbptr)
    {
        carry = (quint64)((quint64)(*aptr) - (quint64)(*bptr) - (quint64)((carry&TWOPOW32U) >> BITPERBLOCK));
        *rptr = (quint32)carry;
        aptr++; bptr++; rptr++;
    }
    while (aptr <= maptr)//可能连续借位
    {
        carry = (quint64)((quint64)(*aptr) - (quint64)((carry&TWOPOW32U) >> BITPERBLOCK));
        *rptr = (quint32)carry;
        aptr++;  rptr++;
    }
    DELFRONTZEROS(tmp_res);
    CPYBN(res, tmp_res);
}

void sub_in_BN(BN a, BN b, BN res) {
    //结果可以用补码表示的减法，如果小减大会出现32个block高位都是1
    int underflow = 0;
    quint32 a_ext[2 + BNMAXBLOCK];
    CPYBN(a_ext, a);
    if (COMPARE(a_ext, b)<0) {
        SETMAXBN(a_ext);
        SETBLOCKNUM(a_ext, BNMAXBLOCK);
        //        SETBLOCKNUM(res,BNMAXBLOCK);
        underflow = 1;
    }
    _sub(a_ext, b, res);
    if (underflow == 1) {
        add_in_BN(res, a, res);
        add_in_BN(res, ONE, res);
    }
    DELFRONTZEROS(res);
}

void sub_u32(BN a, quint32 b, BN res) {
    //减去一个uint32
    BN bn;
    GENBNFROMU32(bn, b);
    sub_in_BN(a, bn, res);
}

void mul_in_BN(BN a, BN b, BN res){
    //保留BN最大二进制位数结果的乘法
    _mul(a,b,res);
    if(GETBLOCKNUM(res) > BNMAXBLOCK){
        SETBLOCKNUM(res, BNMAXBLOCK);
        DELFRONTZEROS(res);
    }
}

void _mul(BN a, BN b, BN res){
    //内部乘法实际过程，结果可能超过BN最大位数
    BND tmp_res;
    memset(tmp_res, 0, sizeof(BND));
    quint32 *aptr,*maptr,*bptr,*mbptr,*rptr;
    quint64 carry = 0ULL;
    if(GETBLOCKNUM(a) == 0 || GETBLOCKNUM(b) == 0){
        CPYBN(res, ZERO);
        return;
    }
    maptr = PTRTOMSDBLOCK(a);
    mbptr = PTRTOMSDBLOCK(b);
    int outer_pos = 0;  //记录外层循环次数
    for(aptr = PTRTOLSDBLOCK(a), rptr = PTRTOLSDBLOCK(tmp_res); aptr <= maptr; aptr++){
        carry = 0ULL; //每次移位重置carry
        for(bptr = PTRTOLSDBLOCK(b); bptr <= mbptr; bptr++,rptr++){
            carry = (quint64)((quint64)(*aptr) * (quint64)(*bptr)) +
                    (quint64)(*rptr) + (quint64)(quint32)(carry >> BITPERBLOCK);
            *rptr = (quint32)carry;
        }
        outer_pos++;
        *rptr += (quint32)(carry >> BITPERBLOCK);
        rptr = PTRTOLSDBLOCK(tmp_res) + outer_pos;
    }
    SETBLOCKNUM(tmp_res, GETBLOCKNUM(a) + GETBLOCKNUM(b));
    DELFRONTZEROS(tmp_res);
    CPYBN(res, tmp_res);
}

quint32 get_bin_bits(BN a){
    //获取BN的二进制位数
    DELFRONTZEROS(a);
    quint32 high,bits , block_num = GETBLOCKNUM(a);
    high = a[block_num];    //high保存BN最高位所在block的uint32
    if(high == 0 && block_num == 0)
        return 0;
    bits = block_num << 5;
    while((high&TWOPOW31U) == 0){
        bits--;
        high = high << 1;
    }
    return bits;
}

void _shift_left(BN a){
    //内部实现的左移，位数会扩展
    //左移一位，位数控制在BN的最大二进制位数
    quint32 *aptr, *maptr, bits;
    quint64 carry = 0;
    DELFRONTZEROS(a);
    bits = get_bin_bits(a);
    if(bits >= (quint32)BNMAXBIT){
        SETBLOCKNUM(a, BNMAXBLOCK);
    }
    maptr = PTRTOMSDBLOCK(a);
    for(aptr = PTRTOLSDBLOCK(a); aptr <= maptr; aptr++){
        carry = (((quint64)(*aptr)) << 1) | (carry >> BITPERBLOCK);
        *aptr = (quint32)carry;
    }
    //如果最后都还进位了（说明原来的最高位是1），需要扩展block数
    if(carry >> BITPERBLOCK){
        if(GETBLOCKNUM(a) < (quint32)BNDMAXBLOCK){
            *aptr = 1U;
            INCBLOCKNUM(a);
        }
    }
    DELFRONTZEROS(a);
}

void shift_left_in_BN(BN a){
    _shift_left(a);
    if(GETBLOCKNUM(a) > BNMAXBLOCK){
        SETBLOCKNUM(a, BNMAXBLOCK);
    }
    DELFRONTZEROS(a);
}

void shift_right(BN a){
    //右移一位
    quint32 *maptr, cur, under_carry = 0;
    if(GETBLOCKNUM(a) == 0) //0不用右移，直接返回
        return;
    for(maptr = PTRTOMSDBLOCK(a); maptr > a; maptr--){
        cur = (quint32)(((quint32)(*maptr) >> 1) | (quint32)(under_carry << (BITPERBLOCK - 1)));
        under_carry = (quint32)((*maptr)&1U);
        *maptr = cur;
    }
    DELFRONTZEROS(a);
}


void slow_div(BN a, BN b, BN quo, BN rem){
    //移位除法，结果可靠但速度较慢
    if(GETBLOCKNUM(b) == 0)
        return; //除零错

    if(COMPARE(a,b) < 0){
        //a<b
        SETZERO(quo);
        CPYBN(rem,a);
        return;
    }
    else if(COMPARE(a,b) == 0){
        CPYBN(quo,ONE);
        CPYBN(rem,ZERO);
        return;
    }
    //a>b时
    BN tmp_quo,tmp_rem, tmp_a, tmp_b, tmp_sub;
    memset(tmp_quo, 0, BNSIZE);
    memset(tmp_rem, 0, BNSIZE);
    memset(tmp_sub, 0, BNSIZE);
//    memset(tmp, 0, BNSIZE);
    CPYBN(tmp_a, a);
    CPYBN(tmp_b, b);
    //如果将block看作BN的位，那么商的位数最多是a的位数-b的位数+1
    SETBLOCKNUM(tmp_quo, GETBLOCKNUM(a) - GETBLOCKNUM(b) + 1);
    int abits = get_bin_bits(tmp_a);
    int bbits = get_bin_bits(tmp_b);
    int shift_num = abits-bbits;
    int sub_time = shift_num + 1;
    for(int i = shift_num; i>0; i--){
        _shift_left(tmp_b);
    }
    for(int i = 0; i < sub_time; i++){
        if(COMPARE(tmp_a,tmp_b) >= 0){
            _sub(tmp_a,tmp_b,tmp_sub);
            CPYBN(tmp_a, tmp_sub);
            _shift_left(tmp_quo);
            add_u32(tmp_quo,1U,tmp_quo);
            shift_right(tmp_b);
        }
        else{
            _shift_left(tmp_quo);
            shift_right(tmp_b);
        }
    }
    CPYBN(quo, tmp_quo);
    CPYBN(rem, tmp_a);
    DELFRONTZEROS(quo);
    DELFRONTZEROS(rem);
}

void knuth_div(BN a, BN b, BN quo, BN rem) {
    //根据Knuth猜商法实现的快速除法
    if (GETBLOCKNUM(b) == 0)
        return; //除零错

    if (COMPARE(a, b) < 0) {
        //a<b
        SETZERO(quo);
        CPYBN(rem, a);
        return;
    }
    else if (COMPARE(a, b) == 0) {
        CPYBN(quo, ONE);
        CPYBN(rem, ZERO);
        return;
    }
    //a>b时
    quint32 tmp_r[2 + BNMAXBLOCK];
    memset(tmp_r, 0, sizeof(tmp_r));
    BN tmp_b, tmp_quo;
    quint32 d, bn_1, bn_2, ri, ri_1, ri_2, qhat;
    quint32 *rptr, *mrptr, *mqptr, *mbptr;
    quint64 carry, borrow, tmp_qhat = 0ULL;
    d = bn_1 = bn_2 = ri = ri_1 = ri_2 = qhat = 0U;
    memset(tmp_b,0,sizeof(BN));
    memset(tmp_r,0,sizeof(BN));
    CPYBN(tmp_r, a);    //给a多填一位，记作r
    CPYBN(tmp_b, b);
    memset(tmp_quo, 0, sizeof(BN));

    //除数只有一个block的话直接调用慢除
    if (GETBLOCKNUM(tmp_b) == 1) {
        slow_div(tmp_r, tmp_b, quo, rem);
        return;
    }
    //1.规格化，使bn_1>=base/2
    mbptr = PTRTOMSDBLOCK(tmp_b);
    bn_1 = *mbptr;
    while (bn_1 < TWOPOW31U) {
        bn_1 = bn_1 << 1;   //注意这个左移仅在bn_1这一块当中，实际上要加上来自bn_2左移的修正，如果bn_2存在的话
        d++;
    }
    int fix_shift_right_num = (int)(BITPERBLOCK - d);
    if (d > 0) {
        //修正bn_1的结果（这里保证除数block数至少为2）
        bn_1 = bn_1 + (quint32)((quint64)(*(mbptr - 1)) >> fix_shift_right_num);
        //修正bn_2的结果
        if (GETBLOCKNUM(tmp_b) > 2) {
            bn_2 = (quint32)((quint64)(*(mbptr - 1)) << d) + (quint32)((quint64)(*(mbptr - 2)) >> fix_shift_right_num);
        }
        else bn_2 = (quint32)((quint64)(*(mbptr - 1)) << d);
    }
    else bn_2 = (quint32)(*(mbptr - 1));

    mrptr = PTRTOMSDBLOCK(tmp_r) + 1;   //指向m+n+1位（被扩充出来的一位）,也是滑动窗口的最高位
    rptr = PTRTOMSDBLOCK(tmp_r) - GETBLOCKNUM(tmp_b) + 1; //滑动窗口末尾，中间一共有lenB个block
    mqptr = tmp_quo + GETBLOCKNUM(tmp_r) - GETBLOCKNUM(tmp_b) + 1;//同样指向q的最高位，可能为0
    mbptr = PTRTOMSDBLOCK(tmp_b);

    while (rptr >= PTRTOLSDBLOCK(tmp_r)) {
        ri = (quint32)((quint64)(*(mrptr)) << d) + (quint32)((quint64)(*(mrptr - 1)) >> fix_shift_right_num);
        ri_1 = (quint32)((quint64)(*(mrptr - 1)) << d) + (quint32)((quint64)(*(mrptr - 2)) >> fix_shift_right_num);
        if (mrptr - 3>tmp_r) {
            ri_2 = (quint32)((quint64)(*(mrptr - 2)) << d) + (quint32)((quint64)(*(mrptr - 3)) >> fix_shift_right_num);
        }
        else ri_2 = (quint32)((quint64)(*(mrptr - 2)) << d);

        //tmp_phat是min{(ri*base+ri_1)/bn_1,base-1},这里的ri,ri-1,bn-1都是经过缩放之后的值
        tmp_qhat = (quint64)((((quint64)ri << BITPERBLOCK) + (quint64)ri_1) / (quint64)bn_1);
        if (tmp_qhat<MAXU32LL) {
            qhat = (quint32)tmp_qhat;
        }
        else qhat = MAXU32L;
        //做步骤4的检验if:bn_2*qhat>(ri*base+ri_1-qhat*bn_1)*base+ri_2 then:qhat-=1
        do {
            quint64 approximate_1 = (quint64)((quint64)ri << BITPERBLOCK) + (quint64)ri_1 - (quint64)qhat*(quint64)bn_1;
            if (approximate_1 >= MAXU32LL)
                break;
            else {
                quint64 approximate_2 = (approximate_1 << BITPERBLOCK) + (quint64)ri_2;
                quint64 approximate_3 = (quint64)bn_2*(quint64)qhat;
                if (approximate_3 > approximate_2)
                    qhat--;
                else
                    break;
            }
        } while (1);

        //步骤5：if r-b*qhat<0,qhat--; 实际上也只有滑动窗口内的ri组成的整数需要验证
        borrow = (quint64)TWOPOW32U;
        carry = 0;
        quint32* tmprptr, *bptr;
        for (bptr = PTRTOLSDBLOCK(tmp_b), tmprptr = rptr; bptr <= mbptr; bptr++, tmprptr++) {
            if (borrow >= TWOPOW32U) {
                //当没有借位的时候
                carry = (quint64)qhat*(quint64)(*bptr) + (quint64)(quint32)(carry >> BITPERBLOCK);
                borrow = (quint64)(*tmprptr) - (quint64)(quint32)carry + TWOPOW32U;
                *tmprptr = (quint32)borrow;
            }
            else {
                carry = (quint64)qhat*(quint64)(*bptr) + (quint64)(quint32)(carry >> BITPERBLOCK);
                borrow = (quint64)(*tmprptr) - (quint64)(quint32)carry + TWOPOW32U - 1ULL;
                *tmprptr = (quint32)borrow;
            }
        }
        //处理r滑动窗口最高位的进位和借位
        if (borrow >= TWOPOW32U) {
            borrow = (quint64)*tmprptr + TWOPOW32U - (quint64)(quint32)(carry >> BITPERBLOCK);
            *tmprptr = (quint32)borrow;
        }
        else {
            //最高位也借位了，说明估商大了，重新加回来一个b
            borrow = (quint64)*tmprptr + TWOPOW32U - (quint64)(quint32)(carry >> BITPERBLOCK) - 1ULL;
            *tmprptr = (quint32)borrow;
        }
        if (borrow < TWOPOW32U)
        {
            carry = 0;
            for (bptr = PTRTOLSDBLOCK(tmp_b), tmprptr = rptr; bptr <= mbptr; bptr++, tmprptr++) {
                carry = (quint64)(*tmprptr) + (quint64)(*bptr) + (quint64)(quint32)(carry >> BITPERBLOCK);
                *tmprptr = (quint32)carry;
            }
            *tmprptr = *tmprptr + (quint32)(carry >> BITPERBLOCK);
            qhat--;
        }
        //得到商并写入q
        *mqptr = qhat; mqptr--;
        //滑动窗口后移一个block
        mrptr--; rptr--;
    }
    SETBLOCKNUM(tmp_quo, GETBLOCKNUM(tmp_r) - GETBLOCKNUM(tmp_b) + 1);
    DELFRONTZEROS(tmp_quo);
    SETBLOCKNUM(tmp_r, GETBLOCKNUM(tmp_b));
    DELFRONTZEROS(tmp_r);
    CPYBN(rem, tmp_r);
    CPYBN(quo, tmp_quo);
}

void mod(BN a, BN n, BN rem){
    //求 a mod n
    DELFRONTZEROS(a);
    DELFRONTZEROS(n);
    if(GETBLOCKNUM(n) == 0){  //如果模数为0
        CPYBN(rem,a);
        return;
    }
    if(GETBLOCKNUM(a) == 0)
    {
        CPYBN(rem,ZERO);
        return;
    }
    else{
        BN tmp_quo,tmp_rem;
        knuth_div(a,n,tmp_quo,tmp_rem);
        CPYBN(rem,tmp_rem);
    }
}

void mod_add(BN a, BN b, BN n, BN rem){
    //求 (a+b)mod n
    DELFRONTZEROS(a);
    DELFRONTZEROS(b);
    DELFRONTZEROS(n);
    if(GETBLOCKNUM(n) == 0)
    {
        _add(a,b,rem);
        return;//模数为0直接返回，出错
    }
    quint32 tmp_add[2 + BNMAXBLOCK];
    memset(tmp_add, 0, sizeof(tmp_add));
    _add(a,b,tmp_add);
    mod(tmp_add,n,rem);
}

void mod_sub(BN a, BN b, BN n, BN rem){
    //求 (a-b)mod n
    DELFRONTZEROS(a);
    DELFRONTZEROS(b);
    DELFRONTZEROS(n);
    if(GETBLOCKNUM(n) == 0)
        return;//模数为0直接返回，出错
    BN tmp_a,tmp_b,tmp_sub;
    CPYBN(tmp_a,a);
    CPYBN(tmp_b,b);
    if(COMPARE(tmp_a,tmp_b)>=0){
        _sub(tmp_a,tmp_b,tmp_sub);
        mod(tmp_sub,n,rem);
    }
    else{
        //a<b, n-[(b-a) mod n]
        BN tmp_rem;
        _sub(tmp_b,tmp_a,tmp_sub);
        mod(tmp_sub,n,tmp_rem);
        _sub(n,tmp_rem,rem);
    }
}

void mod_mul(BN a, BN b, BN n, BN rem){
    //求 (a*b)mod n
    DELFRONTZEROS(a);
    DELFRONTZEROS(b);
    DELFRONTZEROS(n);
    if(GETBLOCKNUM(n) == 0)
        return;//模数为0直接返回，出错
    if(GETBLOCKNUM(a) == 0 || GETBLOCKNUM(b) == 0){
        CPYBN(rem,ZERO);
        return;
    }
    BN tmp_a,tmp_b;
    CPYBN(tmp_a,a);
    CPYBN(tmp_b,b);
    BND tmp_mul;
    _mul(tmp_a,tmp_b,tmp_mul);
    mod(tmp_mul,n,rem);
}

void mont_red_prepare(BN n, BN t0) {
    BN r = { 2,0,1 }; //进制数
    BN t = { 1,1 }; //t
    BN n0_n;
    quint32 n0 = *(PTRTOLSDBLOCK(n));
    GENBNFROMU32(n0_n, n0);
    for (int i = 0; i < (int)(BITPERBLOCK - 1); i++) {
        BN tmp_mul, tmp_t_bn;
        quint32 tmp_t;
        _mul(t, t, tmp_mul);
        tmp_t = *(PTRTOLSDBLOCK(tmp_mul));
        GENBNFROMU32(tmp_t_bn, tmp_t);
        CPYBN(t, tmp_t_bn);       //t<-t*t mod r
        _mul(t, n0_n, tmp_mul);
        tmp_t = *(PTRTOLSDBLOCK(tmp_mul)); //tmp_mul mod r,取tmp_mul的最低位即可
        GENBNFROMU32(tmp_t_bn, tmp_t);
        CPYBN(t, tmp_t_bn);      //t<-t*n mod r
    }
    _sub(r, t, t0);    //t<-r-t
}

void mont_red(BN a, BN b, BN n, BN t, BN rem) {
    //蒙哥马利约简 d' = a*b*r^(-k) mod n,k是模数k的位数
    //计算-n^(-1) mod r
    //BN t;
    BN d = { 0 }, q_bn, a0_b, bi_b, d0_b;
    for (int k = 1; k <= (int)GETBLOCKNUM(n); k++) {
        quint32 bi = b[k], q;
        BN zi_0, tmp_zi, tmp_mul, tmp_add;
        quint32 a0 = *(PTRTOLSDBLOCK(a));
        quint32 d0 = *(PTRTOLSDBLOCK(d));
        //预备计算量
        GENBNFROMU32(a0_b, a0);
        GENBNFROMU32(d0_b, d0);
        GENBNFROMU32(bi_b, bi);
        memset(tmp_add, 0, BNSIZE);
        memset(tmp_mul, 0, BNSIZE);
        memset(tmp_zi, 0, BNSIZE);

        //计算q
        _mul(a0_b, bi_b, tmp_mul);
        _add(tmp_mul, d0_b, zi_0);
        _mul(zi_0, t, tmp_mul);
        q = *(PTRTOLSDBLOCK(tmp_mul));

        //计算d'
        GENBNFROMU32(q_bn, q);
        _mul(q_bn, n, tmp_mul);
        _mul(a, bi_b, tmp_zi);
        _add(tmp_zi, d, tmp_zi);
        _add(tmp_zi, tmp_mul, tmp_add);
        //整体右移一个block
        DELFRONTZEROS(tmp_add);
        //mod(tmp_add, n, tmp_add);
        BN tmp_d;
        memset(tmp_d, 0, BNSIZE);
        if (GETBLOCKNUM(tmp_add) > 1) {
            for (int j = 2; j <= (int)(GETBLOCKNUM(tmp_add)); j++) {
                tmp_d[j - 1] = tmp_add[j];
            }
            *(PTRTOMSDBLOCK(tmp_add)) = 0U;
            SETBLOCKNUM(tmp_d, GETBLOCKNUM(tmp_add) - 1);
            CPYBN(d, tmp_d);
//            mod(d, n, d);
        }
        else CPYBN(d, ZERO);
    }
    if (COMPARE(d, n) >= 0) {
        _sub(d, n, d);
    }
    CPYBN(rem, d);
}


void mont_mul(BN a, BN b, BN n, BN rem) {
    //蒙哥马利模乘：d' = a*b mod n
    DELFRONTZEROS(a);
    DELFRONTZEROS(b);
    DELFRONTZEROS(n);
    //ab=0或者模数为0，直接赋值rem为0并且返回
    if (GETBLOCKNUM(a) == 0 || GETBLOCKNUM(b) == 0 || GETBLOCKNUM(n) == 0)
    {
        CPYBN(rem, ZERO);
        return;
    }
    else if (GETBLOCKNUM(n) > 0 && (*(PTRTOLSDBLOCK(n)) & 1U) == 0) {
        //模数n为偶数，这种情况也是无法使用蒙哥马利约简，且不在考虑范围内，直接调用mod_mul办法求解
        mod_mul(a, b, n, rem);
        return;
    }
    BN an,bn;
    CPYBN(an,a);
    CPYBN(bn,b);
    BN A, B, D, d, t;
    BND pho; //r^(2k)可能会超过(BITPERBLOCK*BNMAXBLOCK)位
    memset(pho, 0, sizeof(BND));
    int k = (int)GETBLOCKNUM(n);
    SETBLOCKNUM(pho, 2 * k + 1);
    pho[2 * k + 1] = 1U;
    mod(pho, n, pho);
    mont_red_prepare(n, t);
//    printf("---------------------- print t----------------\n");
//    printBN(t);
//    printf("================ pho ===========\n");
//    printBN(pho);
    mont_red(an, pho, n, t, A);
//    printf("================ A ===========\n");
//    printBN(A);
    mont_red(bn, pho, n, t, B);
//    printf("================ B ===========\n");
//    printBN(B);
    mont_red(A, B, n, t, D);
//    printf("================ D ===========\n");
//    printBN(D);
    mont_red(D, ONE, n, t, d);
    CPYBN(rem, d);
}

void mont_exp(BN base, BN exp, BN n, BN rem) {
    //蒙哥马利模幂 (base)^(exp) mod n
    DELFRONTZEROS(base);
    DELFRONTZEROS(exp);
    if (GETBLOCKNUM(base) == 0)
    {
        CPYBN(rem, ZERO); //包括了0^0错误
        return;
    }
    //如果幂为0
    if (GETBLOCKNUM(exp) == 0) {
        CPYBN(rem, ONE);
        return;
    }
    BN t;
    BND pho; //r^(2k)可能会超过(BITPERBLOCK*BNMAXBLOCK)位
    memset(pho, 0, sizeof(BND));
    quint32 k = GETBLOCKNUM(n);
    SETBLOCKNUM(pho, 2 * k + 1);
    pho[2 * k + 1] = 1U;
    mod(pho, n, pho);
    mont_red_prepare(n, t);
    BN T, A;
    //进入蒙哥马利域
    mont_red(ONE, pho, n, t, T);  //T = 1*r^k mod n,k是n的r进制位数
    mont_red(base, pho, n, t, A); //A = a*r^k mod n,k是n的r进制位数
    quint32 exp_bin_bits = get_bin_bits(exp);
    for (int i = exp_bin_bits - 1; i >= 0; i--) {
        quint32 block_num = i / (quint32)BITPERBLOCK;
        quint32 block_content = exp[block_num + 1];
        quint32 bit_in_block = i - block_num*(quint32)BITPERBLOCK;
        mont_red(T, T, n, t, T);
        if (((block_content >> (bit_in_block)) & 1U)) {
            mont_red(T, A, n, t, T);
        }
    }
    mont_red(T, ONE, n, t, T);
    CPYBN(rem, T);
}

quint32 gcd(BN a, BN b, BN res){
    //求最大公因数
    DELFRONTZEROS(a);
    DELFRONTZEROS(b);
    BN tmp_rem,tmp_b,tmp_a;
    memset(res, 0, BNSIZE);
    memset(tmp_rem,0,BNSIZE);
    CPYBN(tmp_a,a);
    CPYBN(tmp_b,b);
    if(GETBLOCKNUM(tmp_a) == 0){
        CPYBN(res,tmp_b);
        return 0;
    }
    if(GETBLOCKNUM(tmp_b) == 0){
        CPYBN(res, tmp_a);
        return 0;
    }
    quint32 count = 0;
    BN last_rem;
    CPYBN(last_rem, tmp_b);
    mod(tmp_a,tmp_b,tmp_rem);
    count++;
    while(GETBLOCKNUM(tmp_rem) != 0){
        CPYBN(last_rem,tmp_rem);
        CPYBN(tmp_a,tmp_b);
        CPYBN(tmp_b,tmp_rem);
        mod(tmp_a,tmp_b,tmp_rem);
        count++;
    }
    CPYBN(res,last_rem);
    return count;
}

//为了加快找素数写的
void stein_gcd(BN a, BN b, BN res){
    //化归方法移位求最大公因数
    if(GETBLOCKNUM(a) == 0 || GETBLOCKNUM(b) == 0)
    {
        CPYBN(res,ZERO);
        return;
    }
    quint32 total=0;
    BN tmp,tmp_add,tmp_sub,tmp_a,tmp_b; //使tmp_a始终比tmp_b大
    memset(tmp_a,0,BNSIZE);
    memset(tmp_b,0,BNSIZE);
    if(COMPARE(a, b) < 0){
        CPYBN(tmp_a,b);
        CPYBN(tmp_b,a);
    }
    else{
        CPYBN(tmp_a,a);
        CPYBN(tmp_b,b);
    }
    while(COMPARE(tmp_a,tmp_b) != 0){
        if(tmp_a[1]&1U){
            if(tmp_b[1]&1U){
                //都是奇数
                CPYBN(tmp,tmp_a); //tmp=m
                _add(tmp_a,tmp_b,tmp_add); //add (m,n)
                shift_right(tmp_add);
                CPYBN(tmp_a,tmp_add); //m=(m+n)>>1;
                _sub(tmp,tmp_b,tmp_sub);
                shift_right(tmp_sub);
                CPYBN(tmp_b,tmp_sub);//n=(tmp-n)>>1;
            }
            else{
                shift_right(tmp_b);
            }
        }
        else{ //m为偶数
            if(tmp_b[1]&1U){
                //n为奇数
                shift_right(tmp_a);
                if(COMPARE(tmp_a,tmp_b) < 0){
                    BN tmp_swap;
                    CPYBN(tmp_swap,tmp_a);
                    CPYBN(tmp_a,tmp_b);
                    CPYBN(tmp_b,tmp_swap);
                }
            }
            else{
                shift_right(tmp_a);
                shift_right(tmp_b);
                total++;
            }
        }
    }
    for(quint32 i = 0; i < total; i++){
        shift_left_in_BN(tmp_a);
    }
    CPYBN(res, tmp_a);
}

void inv(BN a, BN n, BN res) {
    //求使得ax mod n = 1 的x,(a,n)=1
    //利用贝祖特定理找逆元：gcd(a,n)=ua+vn;
    memset(res, 0, BNSIZE);
    BN tmp_a, tmp_n;
    int exchange = 0;
    //使得tmp_a指向a和n中较大的数
    if (COMPARE(a, n) < 0) {
        exchange = 1;
        CPYBN(tmp_a, n);
        CPYBN(tmp_n, a);
    }
    else {
        CPYBN(tmp_a, a);
        CPYBN(tmp_n, n);
    }
    BN gcd_a_n;
    quint32 count = gcd(tmp_a, tmp_n, gcd_a_n);
    if (COMPARE(gcd_a_n, ONE) != 0) {
        SETZERO(res);
        return;//如果不互素则没有逆元
    }

    //扩展欧几里得算法
    BN *tmp_quos, *tmp_rems;//记录每一步的商和余数
    BN *tmp_as, *tmp_ns;
    tmp_quos = (BN*)malloc(sizeof(BN)*count);
    tmp_rems = (BN*)malloc(sizeof(BN)*count);
    tmp_as = (BN*)malloc(sizeof(BN)*count);
    tmp_ns = (BN*)malloc(sizeof(BN)*count);
    //    tmp_cofs = (BN)malloc(sizeof(BN)*count);
    //记录求gcd过程的中间变量
    for (quint32 i = 0; i < count; i++) {
        memset(tmp_quos[i], 0, BNSIZE);
        memset(tmp_rems[i], 0, BNSIZE);
        memset(tmp_as[i], 0, BNSIZE);
        memset(tmp_ns[i], 0, BNSIZE);
        //        memset(tmp_cofs[i],0,BNSIZE);
        knuth_div(tmp_a, tmp_n, tmp_quos[i], tmp_rems[i]);
        //printf("%u = %u * %u + %u\n", *(tmp_a + 1), *(tmp_n + 1), *(tmp_quos[i] + 1), *(tmp_rems[i] + 1));
        CPYBN(tmp_as[i], tmp_a);
        CPYBN(tmp_ns[i], tmp_n);
        CPYBN(tmp_a, tmp_n);
        CPYBN(tmp_n, tmp_rems[i]);
//        printf("%u = %u * %u + %u\n", *(tmp_as[i] + 1), *(tmp_ns[i] + 1), *(tmp_quos[i] + 1), *(tmp_rems[i] + 1));
    }
//    printf(" ------ ext gcd ----- \n");
    BN cof_a, cof_n, tmp_t_a, tmp_t_n;
    CPYBN(cof_a, ONE);
    CPYBN(tmp_t_a, ONE);
    CPYBN(cof_n, ZERO);
    CPYBN(tmp_t_n, ZERO);
    for (quint32 i = 0; i < count; i++) {
        //_mul(cof_n, tmp_as[count - i - 1], cof_a);
//        printf("1 = %d * %d + %d * %d\n", *(cof_a + 1), *(tmp_t_a + 1), *(cof_n + 1), *(tmp_t_n + 1));
        BND tmp_cof_n,tmp_sub;  //防止负数相加时堆栈溢出
        CPYBN(tmp_cof_n, cof_n);
        CPYBN(tmp_t_n, tmp_t_a);
        mul_in_BN(tmp_cof_n, tmp_quos[count - i - 1], tmp_sub);
        sub_in_BN(ZERO, tmp_sub, tmp_sub);
        //当两个都是负数相加的时候会出错，要修改
        //牺牲一个表示大数的位数
        int bits1, bits2;
        bits1 = get_bin_bits(cof_a);
        bits2 = get_bin_bits(tmp_sub);
        if (bits1 == (BITPERBLOCK*BNMAXBLOCK) && bits2 == (BITPERBLOCK*BNMAXBLOCK)) {
            //说明这两个数都是负数，为了好算先变成正数
            BN trans1, trans2;
            sub_in_BN(ZERO, tmp_sub, trans1);
            sub_in_BN(ZERO, cof_a, trans2);
            add_in_BN(trans1, trans2, cof_n);
            sub_in_BN(ZERO, cof_n, cof_n);
        }
        else
            add_in_BN(cof_a, tmp_sub, cof_n);
        CPYBN(tmp_t_a, tmp_as[count - i - 1]);
        CPYBN(cof_a, tmp_cof_n);
    }
//    printf("1 = %d * %d + %d * %d\n", *(cof_a + 1), *(tmp_t_a + 1), *(cof_n + 1), *(tmp_t_n + 1));
    if (exchange == 0) {
        //处理负数结果
        if (get_bin_bits(cof_a)==(BITPERBLOCK*BNMAXBLOCK)) {
            sub_in_BN(ZERO, cof_a, res);
            sub_in_BN(a, res, res);
        }
        else CPYBN(res, cof_a);
    }
    else {
        //处理负数结果
        if (get_bin_bits(cof_n) == (BITPERBLOCK*BNMAXBLOCK)) {
            sub_in_BN(ZERO, cof_n, res);
            sub_in_BN(n, res, res);
        }
        else CPYBN(res, cof_n);
    }
}

QString bn2str(BN bn){
    //将BN转换成16进制数的字符串
    DELFRONTZEROS(bn);
    int block_num = GETBLOCKNUM(bn);
    if(block_num == 0)
        return QString("0");
    QString res = "";
    for(int i = block_num; i > 0; i--){
        QString tmp_str;
        quint32 content = bn[i];
        tmp_str = QString::asprintf("%08X",content);
        res.append(tmp_str);
    }
    //去掉前置0
    int zero_len;
    for(zero_len = 0; res.at(zero_len) == '0';zero_len++);
//    cout<<"zero len: " << zero_len<<endl;
//    cout<<res.toStdString().data()<<endl;
    if(zero_len > 0)
        res.remove(0,zero_len);
    return res;
}


void str2bn(BN bn, QString num_str){
    //将16进制字符串转换成BN
//    cout << "str2bn: " << num_str.toStdString().data() << endl;
    num_str.remove("\n");
    int len = num_str.length(); //QString有一个结尾字符
    int total_block = (len % 8) !=0 ? (len>>3)+1:(len>>3); // ceil(len/8)
    total_block = (total_block>BNMAXBLOCK)?BNMAXBLOCK:total_block;
    memset(bn,0,BNSIZE);
    SETBLOCKNUM(bn, total_block);
    if(total_block == 1)
    {
        quint32 content = num_str.toUInt(nullptr,16);
        GENBNFROMU32(bn,content);
        return;
    }
    int start, end = len-1;//子字符串下标
    QString sub_str;
    quint32 content;
    for(int i = 0; i < total_block-1; i++){
        start = end - 7;
        sub_str = num_str.mid(start,8);
        content = sub_str.toUInt(nullptr,16);
        //cout << "content[" << i+1 << "]: " << sub_str.toStdString().data() << ", "<< content << endl;
        bn[i+1] = content;
//        cout<< bn[i+1] <<endl;
        end = start-1;
    }
    sub_str = num_str.mid(0,end+1);
    content = sub_str.toUInt(nullptr,16);
    //cout << "content[" << total_block << "]: " << sub_str.toStdString().data() << ", "<< content << endl;
    bn[total_block] = content;
//    cout<< bn[total_block] <<endl;
}

void write_bn_to_file(BN b, QString file){
    //将bn写到文件
    QFile myfile(file);
    if(myfile.open(QFile::WriteOnly|QFile::Truncate)){
        cout << "open file: " << file.toStdString().data() << endl;
        QTextStream out(&myfile);
        printBN(b);
        QString num_str = bn2str(b);
        out << num_str << endl;
    }
    myfile.close();
}

void read_bn_from_file(BN b, QString file){
    //从文件读bn
    QFile myfile(file);
    if(myfile.open(QIODevice::ReadOnly)){
        char buf[520];
        qint64 linelen = myfile.readLine(buf,sizeof(buf));
//        if(-1!=linelen){
//            printf("read bn : %s",buf);
//        }
        QString str = QString(QLatin1String(buf));
//        cout <<  "read str: " <<str.toStdString().data() << endl;
        str2bn(b,str);
    }
    myfile.close();
}

bool fermat_test(BN p){
    //费马检测
    DELFRONTZEROS(p);
    if(GETBLOCKNUM(p) == 0)
        return false;
    else if(GETBLOCKNUM(p) == 1){
        if(p[1] == 2)
            return true;
        else if(p[1] == 1 || p[1] % 2 == 0) //如果是1或者偶数直接返回
            return false;
    }
    //选取2,3,5,7,11进行费马检测
    BN little_primes[4] = {{1,2},{1,3},{1,5},{1,7}};
    BN tmp_gcd;
    for(int i = 0; i < 4; i++){
        if(COMPARE(p,little_primes[i]) == 0)
            return true; //如果是小素数直接返回
        stein_gcd(p,little_primes[i],tmp_gcd);
        if(tmp_gcd[0] > 1 || tmp_gcd[1] != 1)
            return false;
    }
    BN p_1, tmp_rem;
    _sub(p,ONE,p_1);
    for(int i = 0; i < 4;i++){
        mont_exp(little_primes[i],p_1,p,tmp_rem);
        if(tmp_rem[0] > 1 || tmp_rem[1] != 1)
            return false;
    }
    return true;
}

bool miller_test(BN p, int test_time){
    //miller-rabin检测
    DELFRONTZEROS(p);
    if(p[0] == 0)
        return false;
    if(p[1] == 1)
        return false;
    if(p[0]== 1 && (p[1] == 2 || p[1] == 3)) //2或者3直接返回
        return true;
    //p>3时
    if(p[1] & 1U == 0) return false; //偶数直接返回
    //得到p-1,且将p-1写成2^k*(odd num)
    BN p_1;
    CPYBN(p_1,p);
    p_1[1] = p_1[1] - 1U; //p-1
    //由于进制是2^32,只需要取最低的block计算k值
    int k = 0;
    BN low;
    CPYBN(low,p_1);
    bool flag = true;
    while((low[1] & 1U) == 0){
        k++;
        shift_right(low);   //这里必须是整体右移而不能是低位block单独右移
    }
    //p-1[1] = 2^k*(low_exp)
    srand((int)time(0));
    int max_bits = get_bin_bits(p_1);
//    low_exp[1] = low;

    for(int i = 0; i < test_time; i++){
        BN a,rem;
        gen_rand(a,max_bits);
//        int ran = rand();
//        int ran_bits = rand() % (max_bits/2); //发现每次的bits都太多了，这样生成的数太大了
//        gen_rand(a,ran_bits);
        if(COMPARE(a,p_1) > 0) // 1 <= a <= p-1
            shift_right(a);
        mont_exp(a,low,p,rem);
        if((rem[0] == 1 && rem[1] == 1) || (COMPARE(rem,p_1) == 0)){
            continue;
        }
        for(int j = 0; j <= k-1; j++){
            mont_mul(rem,rem,p,rem);
            if((rem[0] == 1 && rem[1] == 1))
                break;
            else if(COMPARE(rem,p_1) == 0)
                goto endLoop;
        }
        flag = false; //上述循环结束后走这条路，就是合数
        break;
        endLoop:;
    }
    return flag;
}

void gen_rand(BN ran, quint32 bits){
    //产生随机的bits位BN
    if(bits <= 0)
        CPYBN(ran,ZERO);
    int block_num = bits >> 5;
    if((bits % 32) > 0)
        block_num++;
    //最多BNMAXBIT位，多余会截断
    block_num = (block_num > BNMAXBLOCK) ? BNMAXBLOCK : block_num;
    srand((quint32)time(NULL));
    int high_block_bits = bits - ((block_num-1) << 5); //最高位所在block中的二进制位数
    BN a;
    memset(a,0,BNSIZE);
    SETBLOCKNUM(a, block_num);//设置位数，否则会认为是0
    for(int i = block_num - 1; i > 0; i--){
        a[i] = rand()*rand();
    }
    a[block_num] = rand()*rand();
    //看最高位随机数的位数
    int high_bits = 0;
    for(quint32 tmp = a[block_num];;){
        if(tmp == 0U)
            break;
        tmp = tmp>>1;
        high_bits++;
    }
    if(high_bits == high_block_bits){
        CPYBN(ran,a);
        return;
    }
    else if(high_bits > high_block_bits){
        a[block_num] = a[block_num] >> (high_bits-high_block_bits);
    }
    else{
        a[block_num] = a[block_num] << (high_block_bits - high_bits);
    }
    CPYBN(ran,a);
//    printBN(a);
}

void gen_prime_aid(){
    //辅助函数用于计算小素数的乘积
    quint32 first_50_primes[70] = {
        2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,
                127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,
        239,241,251,257,263,269,271,277,281,283,289,307,311,313,317,331,337,347,349
    };
    int pre_nums[7] = {40,45,50,55,60,65,70};
    QString filepath = ":/mul/aid/mul/";
    QString files[7] = {"first40primes_mul.txt","first45primes_mul.txt","first50primes_mul.txt",
                       "first55primes_mul.txt","first60primes_mul.txt","first65primes_mul.txt",
                       "first70primes_mul.txt"};
    BN x,y,z;
    for(int j = 0; j < 7; j++){
        CPYBN(x,ONE);
        for(int k = 0; k < pre_nums[j]; k++){
            GENBNFROMU32(y,first_50_primes[k]);
            _mul(x,y,z);
            CPYBN(x,z);
            DELFRONTZEROS(x);
        }
        write_bn_to_file(x,filepath+files[j]);
    }
}

void gen_prime(BN p,int bits){
    quint32 first_60_primes[50] = {
            2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,
                    127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229
    };
    BN first_60_primes_mul; //前五十个素数的乘积，已经准备好了
    QString filepath = ":/mul/aid/mul/";
    read_bn_from_file(first_60_primes_mul,filepath+"first60primes_mul.txt");
    BN pivot;
    GENBNFROMU32(pivot,first_60_primes[35]);//设置一个gcd的标志
//    QString str = bn2str(first_60_primes_mul);
//    cout << "first 60 primes mul: " << str.toStdString().data() << endl;
    int find_times = 0;
    bool test_result = false;
    BN pos_prime, tmp_gcd;
    memset(pos_prime,0,BNSIZE);
    while(!test_result){
        bool is_prime = false;
        gen_rand(pos_prime,bits);
        //如果是偶数则加1
        if((pos_prime[1]&1U)==0)
            _add(pos_prime,ONE,pos_prime);
        stein_gcd(pos_prime,first_60_primes_mul,tmp_gcd);
        if(COMPARE(tmp_gcd, ONE) == 0){
            //(pos_prime,first_50_primes_mul)=1，即这两个数互素才进入素性检测
            is_prime = miller_test(pos_prime);
//            is_prime = fermat_test(pos_prime);
            find_times++;
            if(is_prime){
                CPYBN(p,pos_prime);
                test_result = true;
                return;
            }
        }
        else if(COMPARE(tmp_gcd, pivot) >= 0 )
        {
            //什么也不做，直接重新生成随机数
        }
        else{
            //如果不和前五十个素数乘积互素，那么一定有一个在前50个素数乘积当中的因素
            //对生成的大数进行调整
            BN adjust;
            CPYBN(adjust,TWO);
            //每二十次探测修改一次步长
            for(int i = 0; i < 20; i++){
                _add(pos_prime,adjust,pos_prime);
                stein_gcd(pos_prime,first_60_primes_mul,tmp_gcd);
                if(COMPARE(tmp_gcd,ONE) == 0){
                    is_prime =miller_test(pos_prime);
                    find_times++;
                    if(is_prime){
                        CPYBN(p,pos_prime);
                        test_result = true;
                        return;
                    }
                }
                else if(COMPARE(tmp_gcd, pivot) > 0){
                    break;
                }
                else{
                    //修改步长
                    _mul(tmp_gcd, adjust, adjust);
                }
            }
        }
    }
}

void gen_prime_chen(BN p, int bits){
    BN first_primes_mul; //前几十个素数的乘积，已经准备好了
    QString filepath = ":/mul/aid/mul/";
    read_bn_from_file(first_primes_mul,filepath+"first50primes_mul.txt");
    BN k1,k2,tmp_p1,tmp_gcd;
    memset(tmp_p1,0,BNSIZE);
    memset(tmp_gcd,0,BNSIZE);
    QString filename1 = ":/prime/aid/prime/prime"+QString::number(bits,10)+"bit.txt";
    //读取特征素数
    read_bn_from_file(k1,filename1.toStdString().data());
//    cout << "k1 bits: " <<get_bin_bits(k1) << endl;
    int random_bits = 128;
    bool flag_p1;
    flag_p1 = false;
    while(flag_p1 == false){
        flag_p1 = false; //默认tmp_p1都不是素数
        gen_rand(k2,random_bits);
        //计算p1（p1是p-1的大素数因子）
        for(quint32 i = 1; i <= 1000; i++){
            if(!flag_p1){
                BN k2_i,k2_i1,i_bn,tmp_mul;
                GENBNFROMU32(i_bn,i);
                _add(k2,i_bn,k2_i); //k2+i
                _add(k2_i,ONE,k2_i1); //k2+i+1
                _mul(k2_i,k2_i1,tmp_mul); //(k2+i+1)(k2+i)
                _add(tmp_mul,k1,tmp_p1);
                stein_gcd(tmp_p1,first_primes_mul,tmp_gcd);
                if(tmp_gcd[0]==1&&tmp_gcd[1]==1)
                    flag_p1 = miller_test(tmp_p1);
            }
            else break;
        }
    }
    CPYBN(p,tmp_p1);
}

//速度看脸，数量级在秒级别，10s以内吧，不符合要求只能辅助
void gen_prime_slow(int bits){
    //产生一个512位的素数存入file中
    BN p1;
    clock_t start = clock();
    gen_prime(p1,bits); //位数稳定但是慢的素数生成
    clock_t end = clock();
    QString filename = ":/prime/aid/prime/prime" + QString::number(bits,10) + "bit.txt";
    cout << "generate one " << get_bin_bits(p1) <<" bits prime cost: " << end-start << " ms" << endl;
    write_bn_to_file(p1,filename.toStdString().data());
}

//使用gcd先判断之后快了很多
void gen_safe_prime(BN p, int bits){
    //产生bits位的安全大素数p
    //bits默认在512,768,1024三个之中（开发环境也有别的，但是应用场景就是这三个其中之一
    //根据陈氏定理：p1 = (k2+n) * [(k2+n)+1] + k1,其中k2为随机大数，k1为特征素数
    //使用提前准备好的大素数文件的程序
    BN first_primes_mul; //前几十个素数的乘积，已经准备好了
    read_bn_from_file(first_primes_mul,":/mul/aid/mul/first60primes_mul.txt");
    BN k1,k2,tmp_p1,tmp_p2,tmp_p,tmp_gcd;
    memset(tmp_p1,0,BNSIZE);
    memset(tmp_p2,0,BNSIZE);
    memset(tmp_p,0,BNSIZE);
    memset(tmp_gcd,0,BNSIZE);
    QString filename1 = ":/prime/aid/prime/prime"+QString::number(bits,10)+"bit.txt";
    //读取特征素数
    read_bn_from_file(k1,filename1.toStdString().data());
    int random_bits = 128;
    bool flag_p1,flag_p2,flag_p;
    flag_p = flag_p1 = flag_p2 = false;
    while(flag_p == false || flag_p1 == false || flag_p2 == false){
        flag_p = flag_p1 = flag_p2 = false; //默认tmp_p,tmp_p1,tmp_p2都不是素数
        gen_rand(k2,random_bits);
        int mt_time1,mt_time2,mt_time3;
        mt_time1 = mt_time2 = mt_time3 = 0;
        //计算p1（p1是p-1的大素数因子）
        for(quint32 i = 1; i <= 1000; i++){
            if(!flag_p1){
                BN k2_i,k2_i1,i_bn,tmp_mul;
                GENBNFROMU32(i_bn,i);
                _add(k2,i_bn,k2_i); //k2+i
                _add(k2_i,ONE,k2_i1); //k2+i+1
                _mul(k2_i,k2_i1,tmp_mul); //(k2+i+1)(k2+i)
                _add(tmp_mul,k1,tmp_p1);
                stein_gcd(tmp_p1,first_primes_mul,tmp_gcd);
                if(tmp_gcd[0]==1&&tmp_gcd[1]==1){
                    flag_p1 = miller_test(tmp_p1);
                    mt_time1++;
                }
            }
            else break;
        }
        //计算p
        for(quint32 j = 1; j <= 1000; j++){
            if(!flag_p){
                BN j2_bn;
                GENBNFROMU32(j2_bn,(j<<1));//k*2
        //        shift_left_in_BN(j_bn); //j*2
                _mul(tmp_p1,j2_bn,tmp_p);
                _add(tmp_p,ONE,tmp_p);
                stein_gcd(tmp_p,first_primes_mul,tmp_gcd);
                if(tmp_gcd[0]==1&&tmp_gcd[1]==1){
                    flag_p = miller_test(tmp_p);
                    mt_time2++;
                }
            }
            else{
                break;
            }
        }
        //计算p2（p2是p+1的大素数因子）
        for(quint32 k = 1; k <= 1000; k++){
            if(!flag_p2){
                BN k2_bn,p_1,rem;
                GENBNFROMU32(k2_bn,(k<<1));
                _add(tmp_p,ONE,p_1);
                knuth_div(p_1,k2_bn,tmp_p2,rem);
                stein_gcd(tmp_p2,first_primes_mul,tmp_gcd);
                if(tmp_gcd[0]==1&&tmp_gcd[1]==1){
                    flag_p2 = miller_test(tmp_p2);
                    mt_time3++;
                }
            }
            else{
                break;
            }
        }
        cout << mt_time1 << " " << mt_time2 << " " << mt_time3 << endl;
    }
    CPYBN(p,tmp_p);
}

void genpq_safe(BN p, BN q, int bits){
    //产生bits位的大素数p,q（实际上是构造方法）
//    clock_t start = clock();
    gen_safe_prime(p,bits);
//    clock_t end = clock();
//    cout<<"p: " << get_bin_bits(p) << " bits and find safe prime cost: " <<  end-start << " ms" << endl;
//    printBN(p);
//    start = clock();
    gen_safe_prime(q,bits);
//    end = clock();
//    cout<<"q: " << get_bin_bits(q) << " bits and find safe prime cost: " <<  end-start << " ms" << endl;
//    printBN(q);
    while(COMPARE(p,q) == 0)
        gen_safe_prime(q,bits);
}

void genpq_unsafe(BN p, BN q, int bits){
    //产生bits位的大素数p,q（实际上是构造方法）
//    clock_t start = clock();
    gen_prime_chen(p,bits);
//    clock_t end = clock();
//    cout<<"p: " << get_bin_bits(p) << " bits and find unsafe prime cost: " <<  end-start << " ms" << endl;
//    printBN(p);
//    start = clock();
    gen_prime_chen(q,bits);
//    end = clock();
//    cout<<"q: " << get_bin_bits(q) << " bits and find unsafe prime cost: " <<  end-start << " ms" << endl;
//    printBN(q);
    while(COMPARE(p,q) == 0)
        gen_prime(q,bits);
}

quint32** initial_keys(int key_type){
    //初始化密钥数组
    int size = (key_type==0)? 2 : 4;
    quint32** key;
    key = (quint32**)malloc(sizeof(quint32*)*size);
    for(int i = 0; i < size;i++){
        key[i] = (quint32*)malloc(sizeof(BN));
    }
    return key;
}

BNPTR** gen_key(int bits){
    BNPTR** keys = (BNPTR**)malloc(sizeof(quint32**)*2);
    keys[0] = initial_keys(0);
    keys[1] = initial_keys(1);
    _gen_key(keys[0],keys[1],bits);
//    printBN(keys[0][0]);
    return keys;
}

void _gen_key(quint32** pb_key, quint32** pr_key, int bits){
//    生成公钥和私钥,bits表示密钥的级别(512/768/1024)
    BN p,q,p_1,q_1,n,fai_n;
    genpq_unsafe(p,q,bits);
    _mul(p,q,n);        //n=pq
    _sub(p,ONE,p_1);    //p-1
    _sub(q,ONE,q_1);    //q-1
    _mul(p_1,q_1,fai_n);//fai(n) = (p-1)(q-1)
    BN default_e,d,tmp_gcd;
    quint32 common_e = 65537;
    GENBNFROMU32(default_e,common_e);
    stein_gcd(fai_n,default_e,tmp_gcd);
    if(!(tmp_gcd[0] == 1 && tmp_gcd[1] == 1)){
        //如果65537和fai(n)不互素，重新生成一个素数作为公钥e
        while(!COMPARE(tmp_gcd,ONE)){
            gen_prime(default_e,17);
            stein_gcd(fai_n,default_e,tmp_gcd);
        }
    }
//    pb_key = (quint32**)malloc(sizeof(quint32*)*2);
//    for(int i = 0; i < 2;i++){
//        pb_key[i] = (quint32*)malloc(sizeof(BN));
//    }

//    pr_key = (quint32**)malloc(sizeof(quint32*)*4);
//    for(int i = 0; i < 4;i++){
//        pr_key[i] = (quint32*)malloc(sizeof(BN));
//    }
    CPYBN(pb_key[0],n);
    CPYBN(pb_key[1],default_e);
    inv(default_e,fai_n,d);
    CPYBN(pr_key[0],p);
    CPYBN(pr_key[1],q);
    CPYBN(pr_key[2],d);
    CPYBN(pr_key[3],fai_n);
//    cout << "p: " << endl;
//    printBN(p);
//    cout << "--------------------------" << endl;
//    cout << "q: " << endl;
//    printBN(q);
//    cout << "--------------------------" << endl;
//    cout << "public e: " << endl;
//    printBN(default_e);
//    cout << "--------------------------" << endl;
//    cout << "private d: " << endl;
//    printBN(d);
//    cout << "--------------------------" << endl;
}

//NO padding
QString encrpyt_message(QString msg, BN e, BN n, int bits){
    //加密，字符串默认中英文可夹杂，转成Unicode字符串之后划分加密（明文长度以字节数为单位）
    //1.msg转成Unicode编码并划分块
    QString cipher_str = "";
//    printBN(e);
//    printBN(n);
//    qDebug() << msg << endl;
//    msg.remove("\n");
//    if()
    QChar* unicodeChars = msg.data();
    QString unistr = "";
    for(int i = 0; i<msg.length();i++){
//        QString unistr;
//        qDebug() << QString::asprintf("%04X",unicodeChars[i].unicode(),16) << endl;
        unistr.append(QString::asprintf("%04X",unicodeChars[i].unicode(),16));
    }
    int bytes = bits >> 3;
    int len = unistr.length();
    int uni_num = len >> 1;//16进制的话两个16进制位才算一个字节
    int encrpyt_time = (uni_num%bytes) == 0? uni_num/bytes:(uni_num/bytes+1);
    //加密
    QString nstr =  bn2str(n);
    for(int i = 0; i < encrpyt_time; i++){
        BN msg,cipher;
        quint32 start,end;
        start = ((quint32)i*bytes) << 1;
        end = (len - (i+1)*bytes*2) > 0?(bytes<<1):(len - (i)*bytes*2);
        QString partial_str = unistr.mid(start,end);
//        qDebug() << "[" << i << "]: "<< start << "," << end << "\n" << partial_str << endl;
        str2bn(msg,partial_str);
        mont_exp(msg,e,n,cipher);
        QString pstr = bn2str(cipher);
//        qDebug() << pstr.length() << endl;
        //处理位数比128小的情况，就添加空格在str后面，不然的话解密有问题
        if(pstr.length() < nstr.length())
            for(int i = 0; i < nstr.length()-pstr.length();i++)
                pstr.append(" ");
        cipher_str.append(pstr); //密文不一定是模数那么多位，可能有-1偏差
//        qDebug() << "[" << i << "]: "<< pstr.length() << "\n" << pstr << endl;
    }
    return cipher_str;
}

QString decrypt_message(QString cipher, BN d, BN n, int bits){
    //解密
//    printBN(d);
//    printBN(n);
//    qDebug() << cipher << endl;
    cipher.remove("\n");
    QString real_text = "", nstr = bn2str(n);
    int block_size = nstr.length(), total_len = cipher.length();
    int decrpyt_time = (total_len%block_size == 0)?total_len/block_size:(total_len/block_size+1);
    for(int i=0;i<decrpyt_time;i++){
        BN msg,demsg;
        int start,end;
        start = i*block_size;
        end = (total_len - (i+1)*block_size) > 0?block_size:(total_len-i*block_size);
        QString partial_str = cipher.mid(start,end);
        partial_str.remove(" ");//去掉填充空格
//        qDebug() << "[" << i << "]: "<< start << "," << end << "\n" << partial_str << endl;
        str2bn(msg,partial_str);
        mont_exp(msg,d,n,demsg);
        QString pstr = bn2str(demsg);
//        qDebug() << "decrypt: " << pstr << endl;
        //前面可能缺0，需要补齐
        if(pstr.length()%4!=0){
            int zero_len = (pstr.length()/4+1)*4-pstr.length();
            for(int j = 0; j < zero_len; j++){
                pstr = "0" + pstr;
            }
        }
        //对得到的字符串还原
//        qDebug() << text.length() << endl;
        for(int i = 0; i < (pstr.length()>>2); i++){
            //再把每一个字符转成Unicode
            quint32 start = i<<2;
            QString oneUnicode = pstr.mid(start,4);
    //        qDebug() << oneUnicode << " "<<endl ;
            QChar ch(oneUnicode.toUShort(nullptr,16));
//            qDebug() << oneUnicode << ", "<< oneUnicode.toUShort(nullptr,16)<<", "<<ch << endl ;
            real_text.append(ch);
        }
//        qDebug() <<endl;
//        qDebug() << real_text << endl;
    }
    return real_text;
}
