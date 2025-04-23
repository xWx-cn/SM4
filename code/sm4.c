#include "sm4.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SM4_BLOCK_SIZE 16
#define ROTL32(x,n)  (((x) << (n)) | ((x) >> (32 - (n))))
#define SWAP(x,y)    { u32 _t = x; x = y; y = _t; }

static const u8 Sbox[256] = {
    0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
    0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
    0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
    0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
    0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
    0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
    0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
    0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
    0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
    0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
    0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
    0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
    0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
    0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
    0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
    0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};

static const u32 FK[4] = {0xA3B1BAC6,0x56AA3350,0x677D9197,0xB27022DC};
static const u32 CK[32] = {
    0x00070E15,0x1C232A31,0x383F464D,0x545B6269,0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
    0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
    0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
    0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,0x10171E25,0x2C333A41,0x484F565D,0x646B7279
};

static u32 tau(u32 x) {
    u8 a0=(x>>24)&0xFF, a1=(x>>16)&0xFF, a2=(x>>8)&0xFF, a3=x&0xFF;
    return ((u32)Sbox[a0]<<24)|((u32)Sbox[a1]<<16)|((u32)Sbox[a2]<<8)|(u32)Sbox[a3];
}
static u32 L(u32 b) {
    return b ^ ROTL32(b,2) ^ ROTL32(b,10) ^ ROTL32(b,18) ^ ROTL32(b,24);
}
static u32 Lp(u32 b) { return b ^ ROTL32(b,13) ^ ROTL32(b,23); }
static u32 T(u32 x)  { return L (tau(x)); }
static u32 Tp(u32 x) { return Lp(tau(x)); }
static u32 round_f(u32 x0,u32 x1,u32 x2,u32 x3,u32 rk) {
    return x0 ^ T(x1 ^ x2 ^ x3 ^ rk);
}

void sm4_key_schedule(const u8 key[16], sm4_context *ctx) {
    u32 MK[4], K[36];
    for(int i=0;i<4;i++){
        MK[i] = ((u32)key[4*i]<<24)|((u32)key[4*i+1]<<16)|((u32)key[4*i+2]<<8)|(u32)key[4*i+3];
        K[i] = MK[i] ^ FK[i];
    }
    for(int i=0;i<32;i++){
        u32 tmp = K[i+1] ^ K[i+2] ^ K[i+3] ^ CK[i];
        K[i+4] = K[i] ^ Tp(tmp);
        ctx->rk[i] = K[i+4];
    }
}

void sm4_encrypt(const u8 in[16], u8 out[16], const sm4_context *ctx) {
    u32 x[4];
    for(int i=0;i<4;i++) x[i] = ((u32)in[4*i]<<24)|((u32)in[4*i+1]<<16)|((u32)in[4*i+2]<<8)|(u32)in[4*i+3];
    for(int i=0;i<32;i++){
        x[0] = round_f(x[0],x[1],x[2],x[3], ctx->rk[i]);
        SWAP(x[0],x[1]); SWAP(x[1],x[2]); SWAP(x[2],x[3]);
    }
    for(int i=0;i<4;i++){
        u32 v = x[3-i];
        out[4*i]   = (u8)(v>>24);
        out[4*i+1] = (u8)(v>>16);
        out[4*i+2] = (u8)(v>>8);
        out[4*i+3] = (u8) v;
    }
}

void sm4_decrypt(const u8 in[16], u8 out[16], const sm4_context *ctx) {
    u32 x[4];
    for(int i=0;i<4;i++) x[i] = ((u32)in[4*i]<<24)|((u32)in[4*i+1]<<16)|((u32)in[4*i+2]<<8)|(u32)in[4*i+3];
    for(int i=31;i>=0;i--){
        x[0] = round_f(x[0],x[1],x[2],x[3], ctx->rk[i]);
        SWAP(x[0],x[1]); SWAP(x[1],x[2]); SWAP(x[2],x[3]);
    }
    for(int i=0;i<4;i++){
        u32 v = x[3-i];
        out[4*i]   = (u8)(v>>24);
        out[4*i+1] = (u8)(v>>16);
        out[4*i+2] = (u8)(v>>8);
        out[4*i+3] = (u8) v;
    }
}

void sm4_ecb_encrypt(const u8 *in,u8 *out,int len,const u8 iv[16],const sm4_context *ctx){
    (void)iv;
    int full = len/SM4_BLOCK_SIZE;
    for(int i=0;i<full;i++) sm4_encrypt(in+i*16, out+i*16, ctx);
    if(len%SM4_BLOCK_SIZE) memcpy(out+full*16, in+full*16, len%SM4_BLOCK_SIZE);
}

void sm4_ecb_decrypt(const u8 *in,u8 *out,int len,const u8 iv[16],const sm4_context *ctx){
    (void)iv;
    int full = len/SM4_BLOCK_SIZE;
    for(int i=0;i<full;i++) sm4_decrypt(in+i*16, out+i*16, ctx);
    if(len%SM4_BLOCK_SIZE) memcpy(out+full*16, in+full*16, len%SM4_BLOCK_SIZE);
}

void sm4_cbc_encrypt(const u8 *in,u8 *out,int len,const u8 iv[16],const sm4_context *ctx){
    u8 feedback[16]; memcpy(feedback, iv, 16);
    int full = len/SM4_BLOCK_SIZE, rem = len%SM4_BLOCK_SIZE;
    for(int i=0;i<full;i++){
        u8 buf[16];
        for(int j=0;j<16;j++) buf[j] = in[i*16+j] ^ feedback[j];
        sm4_encrypt(buf, out+i*16, ctx);
        memcpy(feedback, out+i*16, 16);
    }
    if(rem) memcpy(out+full*16, in+full*16, rem);
}

void sm4_cbc_decrypt(const u8 *in,u8 *out,int len,const u8 iv[16],const sm4_context *ctx){
    u8 feedback[16]; memcpy(feedback, iv, 16);
    int full = len/SM4_BLOCK_SIZE, rem = len%SM4_BLOCK_SIZE;
    for(int i=0;i<full;i++){
        u8 buf[16], ciph[16];
        /* 1）先保存本轮密文块 */
        memcpy(ciph, in + i*16, 16);
        /* 2）解密，然后写回明文 */
        sm4_decrypt(ciph, buf, ctx);
        for(int j=0;j<16;j++) out[i*16+j] = buf[j] ^ feedback[j];
        /* 3）把原始密文做为下轮反馈 */
        memcpy(feedback, ciph, 16);
    }
    if(rem) memcpy(out+full*16, in+full*16, rem);
}

void sm4_cfb_encrypt(const u8 *in,u8 *out,int len,const u8 iv[16],const sm4_context *ctx){
    u8 feedback[16]; memcpy(feedback, iv, 16);
    int full = len/SM4_BLOCK_SIZE, rem = len%SM4_BLOCK_SIZE;
    for(int i=0;i<full;i++){
        u8 buf[16]; sm4_encrypt(feedback, buf, ctx);
        for(int j=0;j<16;j++) out[i*16+j] = in[i*16+j] ^ buf[j];
        memcpy(feedback, out+i*16, 16);
    }
    if(rem){ u8 buf[16]; sm4_encrypt(feedback, buf, ctx);
        for(int j=0;j<rem;j++) out[full*16+j] = in[full*16+j] ^ buf[j];
    }
}

void sm4_cfb_decrypt(const u8 *in,u8 *out,int len,const u8 iv[16],const sm4_context *ctx){
    u8 feedback[16]; memcpy(feedback, iv, 16);
    int full = len/SM4_BLOCK_SIZE, rem = len%SM4_BLOCK_SIZE;
    for(int i=0;i<full;i++){
       u8 buf[16], ciph[16];
       /* 1）先保存本轮密文块 */
       memcpy(ciph, in + i*16, 16);
       /* 2）生成密钥流并解密写回明文 */
       sm4_encrypt(feedback, buf, ctx);
       for(int j=0;j<16;j++) out[i*16+j] = ciph[j] ^ buf[j];
       /* 3）把原始密文做为下轮反馈 */
       memcpy(feedback, ciph, 16);
        
    }
    if(rem){ 
        u8 buf[16];
        sm4_encrypt(feedback, buf, ctx);
        for(int j=0;j<rem;j++)
        out[full*16+j] = in[full*16+j] ^ buf[j];
    }
}

void sm4_ofb_encrypt(const u8 *in,u8 *out,int len,const u8 iv[16],const sm4_context *ctx){
    u8 feedback[16]; memcpy(feedback, iv, 16);
    int full = len/SM4_BLOCK_SIZE, rem = len%SM4_BLOCK_SIZE;
    for(int i=0;i<full;i++){
        u8 buf[16]; sm4_encrypt(feedback, buf, ctx);
        for(int j=0;j<16;j++) out[i*16+j] = in[i*16+j] ^ buf[j];
        memcpy(feedback, buf, 16);
    }
    if(rem){ u8 buf[16]; sm4_encrypt(feedback, buf, ctx);
        for(int j=0;j<rem;j++) out[full*16+j] = in[full*16+j] ^ buf[j];
    }
}

void sm4_ctr_encrypt(const u8 *in,u8 *out,int len,const u8 iv[16],const sm4_context *ctx){
    u8 counter[16], stream[16]; memcpy(counter, iv, 16);
    int blocks = (len+15)/SM4_BLOCK_SIZE, rem = len;
    for(int i=0;i<blocks;i++){
        sm4_encrypt(counter, stream, ctx);
        int chunk = rem>16?16:rem;
        for(int j=0;j<chunk;j++) out[i*16+j] = in[i*16+j] ^ stream[j];
        rem -= chunk;
        for(int k=15;k>=0;k--) if(++counter[k]) break;
    }
}


// —— PKCS#7 填充／去填充封装
static int pkcs7_pad(const u8 *in, int in_len, u8 **out){
    int pad = SM4_BLOCK_SIZE - (in_len % SM4_BLOCK_SIZE);
    int total = in_len + pad;
    *out = malloc(total);
    memcpy(*out, in, in_len);
    memset(*out + in_len, pad, pad);
    return total;
}
static int pkcs7_unpad(u8 *buf, int buf_len){
    int pad = buf[buf_len-1];
    if(pad < 1 || pad > SM4_BLOCK_SIZE) return buf_len;
    for(int i=0;i<pad;i++) if(buf[buf_len-1-i] != pad) return buf_len;
    return buf_len - pad;
}

#define DEFINE_PKCS7_FN(NAME) \
int sm4_##NAME##_pkcs7_encrypt(const u8 *in, int in_len, u8 *out, const u8 iv[16], const sm4_context *ctx) { \
    u8 *buf; \
    int total = pkcs7_pad(in, in_len, &buf); \
    sm4_##NAME##_encrypt(buf, out, total, iv, ctx); \
    free(buf); \
    return total; \
} \
int sm4_##NAME##_pkcs7_decrypt(const u8 *in, int in_len, u8 *out, const u8 iv[16], const sm4_context *ctx) { \
    sm4_##NAME##_decrypt(in, out, in_len, iv, ctx); \
    return pkcs7_unpad(out, in_len); \
}

DEFINE_PKCS7_FN(ecb)
DEFINE_PKCS7_FN(cbc)
DEFINE_PKCS7_FN(ctr)
DEFINE_PKCS7_FN(cfb)
DEFINE_PKCS7_FN(ofb)

// 简单测试，打印单块明/密/解
void test_sm4(void){
    sm4_context ctx;
    u8 key[16]={0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
    u8 pt[16]={0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};
    u8 ct[32], dt[32];
    sm4_key_schedule(key,&ctx);
    int clen = sm4_ecb_pkcs7_encrypt(pt,16,ct,NULL,&ctx);
    int plen = sm4_ecb_pkcs7_decrypt(ct,clen,dt,NULL,&ctx);
    printf("PT: "); for(int i=0;i<16;i++) printf("%02X",pt[i]);
    printf("\nCT: "); for(int i=0;i<clen;i++) printf("%02X",ct[i]);
    printf("\nDT: "); for(int i=0;i<plen;i++) printf("%02X",dt[i]);
    printf("\n");
}

//如果想要单独测试加解密模块可以取消此处注释，还原主函数入口
//int main(void){
//   test_sm4();
//   return 0;
//}