#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sm4.h"

#pragma pack(push,1)
typedef struct {
    uint16_t bfType;
    uint32_t bfSize;
    uint16_t bfReserved1, bfReserved2;
    uint32_t bfOffBits;
} BITMAPFILEHEADER;
typedef struct {
    uint32_t biSize;
    int32_t  biWidth, biHeight;
    uint16_t biPlanes, biBitCount;
    uint32_t biCompression, biSizeImage;
    int32_t  biXPelsPerMeter, biYPelsPerMeter;
    uint32_t biClrUsed, biClrImportant;
} BITMAPINFOHEADER;
#pragma pack(pop)

int main(int argc, char *argv[]) {
    if (argc < 2 || (argv[1][0]!='e' && argv[1][0]!='d')) {
        fprintf(stderr,
            "Usage:\n"
            "  %s e input.bmp   # Encrypt\n"
            "  %s d             # Decrypt enc_*.bmp\n",
            argv[0], argv[0]);
        return 1;
    }
    int do_encrypt = (argv[1][0] == 'e');
    const char *input  = do_encrypt ? argv[2] : NULL;

    /* 固定测试用密钥/IV */
    u8 key[16] = {
        0x01,0x23,0x45,0x67, 0x89,0xAB,0xCD,0xEF,
        0xFE,0xDC,0xBA,0x98, 0x76,0x54,0x32,0x10
    };
    u8 iv0[16] = {0};

    const char *modes[5] = {"ecb","cbc","cfb","ofb","ctr"};
    sm4_context ctx;

    for (int m = 0; m < 5; m++) {
        char inname[64], outname[64];
        if (do_encrypt) {
            snprintf(inname,  sizeof inname,  "%s",            input);
            snprintf(outname, sizeof outname, "enc_%s.bmp", modes[m]);
        } else {
            snprintf(inname,  sizeof inname,  "enc_%s.bmp", modes[m]);
            snprintf(outname, sizeof outname, "dec_%s.bmp", modes[m]);
        }

        /* 1. 打开文件、读头和像素区 */
        FILE *fin = fopen(inname, "rb");
        if (!fin) { perror(inname); continue; }

        BITMAPFILEHEADER fh;
        BITMAPINFOHEADER ih;
        if (fread(&fh, sizeof fh, 1, fin)!=1 ||
            fread(&ih, sizeof ih, 1, fin)!=1)
        {
            fclose(fin);
            fprintf(stderr, "Invalid BMP: %s\n", inname);
            continue;
        }
        if (fh.bfType != 0x4D42) { fclose(fin); continue; }

        uint32_t offset  = fh.bfOffBits;
        uint32_t datalen = ih.biSizeImage
                         ? ih.biSizeImage
                         : (fh.bfSize - offset);

        uint8_t *header = malloc(offset);
        uint8_t *pixels = malloc(datalen);
        if (!header||!pixels) { fclose(fin); perror("malloc"); return 1; }

        fseek(fin, 0, SEEK_SET);
        fread(header, 1, offset, fin);
        fseek(fin, offset, SEEK_SET);
        fread(pixels, 1, datalen, fin);
        fclose(fin);

        /* 2. 生成子密钥表，并对整个像素区一次性加/解密 */
        sm4_key_schedule(key, &ctx);
        if (do_encrypt) {
            switch (m) {
                case 0: sm4_ecb_encrypt(pixels, pixels, datalen, iv0, &ctx); break;
                case 1: sm4_cbc_encrypt(pixels, pixels, datalen, iv0, &ctx); break;
                case 2: sm4_cfb_encrypt(pixels, pixels, datalen, iv0, &ctx); break;
                case 3: sm4_ofb_encrypt(pixels, pixels, datalen, iv0, &ctx); break;
                case 4: sm4_ctr_encrypt(pixels, pixels, datalen, iv0, &ctx); break;
            }
        } else {
            switch (m) {
                case 0: sm4_ecb_decrypt(pixels, pixels, datalen, iv0, &ctx); break;
                case 1: sm4_cbc_decrypt(pixels, pixels, datalen, iv0, &ctx); break;
                case 2: sm4_cfb_decrypt(pixels, pixels, datalen, iv0, &ctx); break;
                case 3: sm4_ofb_decrypt(pixels, pixels, datalen, iv0, &ctx); break;
                case 4: sm4_ctr_decrypt(pixels, pixels, datalen, iv0, &ctx); break;
            }
        }

        /* 3. 写回 BMP */
        FILE *fout = fopen(outname, "wb");
        if (!fout) { perror(outname); return 1; }
        fwrite(header, 1, offset, fout);
        fwrite(pixels, 1, datalen, fout);
        fclose(fout);

        free(header);
        free(pixels);
        printf("%s %s -> %s\n",
               do_encrypt ? "Encrypted" : "Decrypted",
               modes[m], outname);
    }

    return 0;
}
