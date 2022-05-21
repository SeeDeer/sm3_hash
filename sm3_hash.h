/************************************************************************
 * @file:       sm3_hash.c
 * @author:     SeeDeer18@foxmail.com
 * @brief:      国密SM3密码杂凑算法实现, 参考国家密码管理局2010年公告算法
 * @version:    1.0.0
 * @LastEditTime: 2022-05-22 00:38:43
 * @attention: http://www.oscca.gov.cn/sca/xxgk/2010-12/17/content_1002389.shtml
 *************************************************************************/
#ifndef _SM3_HASH_H_
#define _SM3_HASH_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// sm3类型定义，用于hash值计算
typedef struct sm3_hash
{
    uint32_t iv[8];
    uint32_t message_length;        // 参与计算的消息总长度
    uint8_t buf[64];                // 512比特一组的消息B'
    uint32_t cur_len;               // 组消息B'长度, 不足512比特进行填充
}sm3_hash_t;

void sm3_init(sm3_hash_t *sm3_handle);

void sm3_done(sm3_hash_t *sm3_handle, uint8_t hash[32]);

void sm3_process(sm3_hash_t *sm3_handle, const uint8_t message[], uint32_t length);

#ifdef __cplusplus
}
#endif

#endif
