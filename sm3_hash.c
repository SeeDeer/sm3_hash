/************************************************************************
 * @file:       sm3_hash.c
 * @author:     SeeDeer18@foxmail.com
 * @brief:      国密SM3密码杂凑算法实现, 参考国家密码管理局2010年公告算法
 * @version:    1.0.0
 * @LastEditTime: 2022-05-22 13:58:09
 * @attention: http://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml
 *************************************************************************/
#include "sm3_hash.h"
#include <string.h>

// 8个初始值寄存器
#define IV_A    0x7380166f 
#define IV_B    0x4914b2b9 
#define IV_C    0x172442d7 
#define IV_D    0xda8a0600 
#define IV_E    0xa96f30bc 
#define IV_F    0x163138aa 
#define IV_G    0xe38dee4d 
#define IV_H    0xb0fb0e4e

// 常量 Tj
#define T00_15   0x79cc4519
#define T16_63   0x7a879d8a

// 布尔函数
#define FFj_0015(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define FFj_1663(X,Y,Z) (((X) & (Y)) | ((X) & (Z)) | ((Y) & (Z)))
#define GGj_0015(X,Y,Z) ((X) ^ (Y) ^ (Z))
#define GGj_1663(X,Y,Z) (((X) & (Y)) | ((~(X)) & (Z)))

// 置换函数 P
#define SM3_CYCLE_LEFT(n,k)  (((uint32_t)(n) >> (32-(k))) | ((uint32_t)(n) << (k)))   // ≪ k：循环左移k比特运算
#define SM3_P0(x)   ((uint32_t)(x) ^ SM3_CYCLE_LEFT(x,9) ^ SM3_CYCLE_LEFT(x,17))
#define SM3_P1(x)   ((uint32_t)(x) ^ SM3_CYCLE_LEFT(x,15) ^ SM3_CYCLE_LEFT(x,23))

// 消息扩展, 消息B'扩展为W和W', 共68+64个字
static void msg_expand_B1_W(uint8_t b1[64], uint32_t w[68])
{
    // sm3_printf(b1,64);

    int j = 0, i = 0;
    // 将消息分组B(i)划分为16个字W0; W1; · · · ; W15(处理好大小端)
    for (j = 0; j < 16; j++) {
        i = j << 2;
        w[j] =  (uint32_t)b1[i] << 24;
        w[j] += (uint32_t)b1[i + 1] << 16;
        w[j] += (uint32_t)b1[i + 2] << 8;
        w[j] += (uint32_t)b1[i + 3] << 0;
    }

    // sm3_printf_32(w,16);
    
    // Wj P1(Wj−16 ⊕ Wj−9 ⊕ (Wj−3 ≪ 15)) ⊕ (Wj−13 ≪ 7) ⊕ Wj−6
    for (j = 16; j < 68; j++) {
        w[j] = SM3_P1(w[j-16] ^ w[j-9] ^ SM3_CYCLE_LEFT(w[j-3],15)) ^ SM3_CYCLE_LEFT(w[j-13],7) ^ w[j-6];
    }
}
static void msg_expand_W_W1(uint32_t w[], uint32_t w1[])
{
    int j = 0;
    // W′j = Wj ⊕ Wj+4
    for (j = 0; j < 64; j++) {
        w1[j] = w[j] ^ w[j+4];
    }
}

// 压缩函数
static void cf(uint32_t V[], uint32_t W[], uint32_t W1[])
{
    uint32_t A = V[0];
    uint32_t B = V[1];
    uint32_t C = V[2];
    uint32_t D = V[3];
    uint32_t E = V[4];
    uint32_t F = V[5];
    uint32_t G = V[6];
    uint32_t H = V[7];

    uint32_t SS1 = 0, SS2 = 0;
    uint32_t TT1 = 0, TT2 = 0;
    uint32_t Tjj = T00_15;

    int j = 0;
    for (j = 0; j < 64; j++) {
        // SS1 = ((A ≪ 12) + E + (Tj ≪ j)) ≪ 7
        // 注意处理好 (Tj ≪ j)
        // Tj = (j > 15 ) ? T16_63 : T00_15;
        if (j == 16) {
            Tjj = SM3_CYCLE_LEFT(T16_63, 16);
        } else if (j > 0) {
            Tjj = SM3_CYCLE_LEFT(Tjj, 1);
        }
        SS1 = SM3_CYCLE_LEFT((SM3_CYCLE_LEFT(A,12) + E + Tjj),7);
        // SS2 = SS1 ⊕ (A ≪ 12)
        SS2 = SS1 ^ SM3_CYCLE_LEFT(A,12);
        // TT1 = FFj(A; B; C) + D + SS2 + Wj
        if (j > 15) {
            TT1 = FFj_1663(A,B,C) + D + SS2 + W1[j];
        } else {
            TT1 = FFj_0015(A,B,C) + D + SS2 + W1[j];
        }
        // TT2 = GGj(E; F; G) + H + SS1 + W
        if (j > 15) {
            TT2 = GGj_1663(E,F,G) + H + SS1 + W[j];
        } else {
            TT2 = GGj_0015(E,F,G) + H + SS1 + W[j];
        }
        D = C;
        C = SM3_CYCLE_LEFT(B,9);
        B = A;
        A = TT1;
        H = G;
        G = SM3_CYCLE_LEFT(F,19);
        F = E;
        E = SM3_P0(TT2);
    }
    
    // V(i+1) = ABCDEFGH ⊕ V(i)
    V[0] ^= A;
    V[1] ^= B;
    V[2] ^= C;
    V[3] ^= D;
    V[4] ^= E;
    V[5] ^= F;
    V[6] ^= G;
    V[7] ^= H;
}

static void sm3_compress(sm3_hash_t *sm3_handle)
{
    uint32_t w[68];
    uint32_t w1[64];

    msg_expand_B1_W((uint8_t *)&sm3_handle->buf[0], w);
    msg_expand_W_W1(w,w1);
    cf(sm3_handle->iv,w,w1);
}

void sm3_process(sm3_hash_t *sm3_handle, const uint8_t message[], uint32_t length)
{
    while (length--) {
        sm3_handle->buf[sm3_handle->cur_len] = *message++;
        if (++sm3_handle->cur_len == 64) {
            sm3_compress(sm3_handle);
            sm3_handle->message_length += 512;
            sm3_handle->cur_len = 0;
        }
    }
}

void sm3_done(sm3_hash_t *sm3_handle, uint8_t hash[32])
{
    // 参与校验的消息总比特位数 l
    sm3_handle->message_length += sm3_handle->cur_len * 8;
    // 附加比特1和K个0, k满足 l + 1 + k ≡ 448mod512的最小非负整数
    uint8_t index = sm3_handle->cur_len;    // 一定 < 64
    sm3_handle->buf[sm3_handle->cur_len++] = 0x80;

    if (sm3_handle->cur_len > 56) {
        while (sm3_handle->cur_len < 64) {
            sm3_handle->buf[sm3_handle->cur_len++] = 0x00;
        }
        sm3_compress(sm3_handle);
        sm3_handle->cur_len = 0;
    }
    
    while (sm3_handle->cur_len < 56) {
        sm3_handle->buf[sm3_handle->cur_len++] = 0x00;
    }
    // 56~64, 填充64比特消息长度(暂且只支持32位系统，2^32为最大长度)
    sm3_handle->buf[sm3_handle->cur_len++] = 0x00;
    sm3_handle->buf[sm3_handle->cur_len++] = 0x00;
    sm3_handle->buf[sm3_handle->cur_len++] = 0x00;
    sm3_handle->buf[sm3_handle->cur_len++] = 0x00;
    sm3_handle->buf[sm3_handle->cur_len++] = (sm3_handle->message_length >> 24) & 0xff;
    sm3_handle->buf[sm3_handle->cur_len++] = (sm3_handle->message_length >> 16) & 0xff;
    sm3_handle->buf[sm3_handle->cur_len++] = (sm3_handle->message_length >> 8) & 0xff;
    sm3_handle->buf[sm3_handle->cur_len++] = (sm3_handle->message_length >> 0) & 0xff;
    // printf("cur_len:%d \r\n",sm3_handle->cur_len);
    sm3_compress(sm3_handle);
    // sm3_printf_32(sm3_handle->iv,sizeof(sm3_handle->iv)/sizeof(sm3_handle->iv[0]));
    int i = 0, j = 0;
    for (; i < sizeof(sm3_handle->iv)/sizeof(sm3_handle->iv[0]); i++) {
        j = i << 2;
        hash[j] = (sm3_handle->iv[i] >> 24) & 0xff;
        hash[j + 1] = (sm3_handle->iv[i] >> 16) & 0xff;
        hash[j + 2] = (sm3_handle->iv[i] >> 8) & 0xff;
        hash[j + 3] = (sm3_handle->iv[i] >> 0) & 0xff;
    }
}

void sm3_init(sm3_hash_t *sm3_handle)
{
    memset(sm3_handle,0,sizeof(sm3_hash_t));
    sm3_handle->iv[0] = IV_A;
    sm3_handle->iv[1] = IV_B;
    sm3_handle->iv[2] = IV_C;
    sm3_handle->iv[3] = IV_D;
    sm3_handle->iv[4] = IV_E;
    sm3_handle->iv[5] = IV_F;
    sm3_handle->iv[6] = IV_G;
    sm3_handle->iv[7] = IV_H;
}

#if 1
#include <stdio.h>
#include <sys/time.h>

// 网页版核对工具 https://the-x.cn/hash/ShangMi3Algorithm.aspx

static long get_sys_ustime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    long us_tv = tv.tv_sec * 1000000 + tv.tv_usec;
    return us_tv;
}

int main(int argc, char *argv[])
{
    sm3_hash_t sm3_test;
    sm3_init(&sm3_test);
    uint8_t hash[32] = {0};

    long cost_time1 = 0;
    long cost_time2 = 0;

#if 0
    uint8_t file_buf[4*1024*1024] = {0};
    int ret = 0;
    FILE *fp = fopen(argv[1],"r");
    cost_time1 = get_sys_ustime();
    while (!feof(fp)) {
        ret = fread(file_buf,1,sizeof(file_buf),fp);
        sm3_process(&sm3_test,file_buf,ret);
    }
    cost_time2 = get_sys_ustime();
    printf("cost_time:%ldus\r\n",cost_time2-cost_time1);
    fclose(fp);
#else
    uint8_t test_data[] = {0x01,0x02,0x03,0x04,0x05,0x06};
    sm3_process(&sm3_test,test_data,sizeof(test_data));
#endif
    sm3_done(&sm3_test,hash);

    printf("calculate sm3 hash:");
    for (int i = 0; i < sizeof(hash); i++) {
        printf("%02x",hash[i]);
    }
    printf("\r\n");

    return 0;
}
#endif
