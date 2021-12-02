#include "aes.h"
#include <stdio.h>
#include  <string.h>
#include <stdlib.h>
/*
데이터 비교용 
memcmp(string.h) 함수를 사용할 수 있다면 대체해도 됨.
*/
int myMemcmp(const void *s1, const void *s2, size_t n)
{       
    const unsigned char *su1 = (const unsigned char *)s1;
    const unsigned char *su2 = (const unsigned char *)s2;

    for (; 0 < n; ++su1, ++su2, --n)
      if (*su1 != *su2)
        return (*su1 < *su2 ? -1 : +1);
    return (0);
}

//복호화 테스트 함수
static int test_decrypt_cbc(void)
{
    //암호화 키 공개키 고정값
    unsigned char key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    //초기화 벡터값 램덤형태로 계속 변화를 줘야함.
    unsigned char iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    //입력 데이터 암호화 된 상태의 값
    unsigned char in[]  = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };

    //in 데이터가 해독되면 나와야 하는 데이터 - 비교용
    unsigned char out[] = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };

    //aes 구조체                       
    struct AES_ctx ctx;

    //초기화 벡터값과 공개키로 RoundKey 생성 - 이곳에서 시간 소모가 가장 큼
    AES_init_ctx_iv(&ctx, key, iv);
    /*
      실제 암호 해독 함수 
      aes 구조체 포인터, 암호 데이터, 데이터 길이
      해독된 데이터는 in 변수를 통해 얻을 수 있다.
    */ 
    AES_CBC_decrypt_buffer(&ctx, in, 64);

    printf("CBC decrypt: ");
    /*
     미리 해독해둔 out 변수와 현재 해독된 in 변수를 비교하여
     동일하면 제대로 해독이 된 것으로 간주
    */
    if (0 == myMemcmp((char*) out, (char*) in, 64)) {
        printf("SUCCESS!\n");
	return(0);
    } else {
        printf("FAILURE!\n");
	return(1);
    }
}

//암호화 테스트 함수
static int test_encrypt_cbc(void)
{
    //암호화 키 공개키 고정값
    unsigned char key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    //초기화 벡터값 램덤형태로 계속 변화를 줘야함.
    unsigned char iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    //암호화 되기 전 데이터 - 실제 데이터
    unsigned char in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };

    //in 변수가 암호화된 데이터 - 비교용 
    unsigned char out[] = { 0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d,
                      0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2,
                      0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16,
                      0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7 };
    
    //암호화된 데이터를 받기 위한 변수
    unsigned char inConv[64];               

    //aes 구조체       
    struct AES_ctx ctx;

    //초기화 벡터값과 공개키로 RoundKey 생성 - 이곳에서 시간 소모가 가장 큼
    AES_init_ctx_iv(&ctx, key, iv);

    /*
    실제 암호화 함수
    aes 구조체 포인터, 원본 데이터, 결과를 저장할 변수, 데이터 길이
    암호화된 데이터는 inConv 변수를 통해 받을 수 있다. 
    */
    AES_CBC_encrypt_bufferEx(&ctx, in, inConv, 64);   

    
    printf("CBC encrypt: ");
    //미리 정상적으로 암호화해둔 데이터(out)와 현재 암호화한 데이터(inConv)가 동일하다면 성공
    if (0 == myMemcmp((char*) out, (char*)inConv, 64)) {
        printf("SUCCESS!\n");
	    return(0);
    } else {
        printf("FAILURE!\n");
	    return(1);
    }
}

int enctest(void)
{
    int exit;
    exit = test_encrypt_cbc();    
    exit += test_decrypt_cbc();
    return exit;
}

int main(int argc, char *argv[]) {
    FILE *fp = NULL;
    int size = 0;
    char *buffer = NULL;
    int count = 0;

    FILE *fpOut = NULL;
    FILE *fpIn = NULL;
    int i = 0;
    char *EncBuff = NULL;
    char *inbuffer = NULL;
    char *DecBuff = NULL;
    //unsigned char Key[]={0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x47, 0x77, 0x11, 0x1E, 0x3c};
    //암호화 키 공개키 고정값
    unsigned char key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    
    //초기화 벡터값 램덤형태로 계속 변화를 줘야함.
    unsigned char iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    //초기화 벡터값 램덤형태로 계속 변화를 줘야함.
    unsigned char iv1[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    //aes 구조체       
    struct AES_ctx ctx;
    struct AES_ctx ctx1;

    char *test_buff = NULL;
    char *test_buff1 = NULL;
    char *test_buff2 = NULL;
    char test_file[] = "config.bin";
    printf("FileName[%s]\r\n", argv[1]);
    //file open
    fp = fopen(argv[1],"r");
    //file size check
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    printf("file size = %d \r\n", size);
    //file read data
    buffer = calloc(size +11, sizeof(char));
    fseek(fp, 0, SEEK_SET);
    count = fread(buffer, size, 1, fp);
    printf("start read buffer============================\r\n");
    printf("%s", buffer);
    printf("\r\nend read buffer============================\r\n");

    AES_CBC_encrypt_File(buffer, test_file);
    test_buff = calloc(2500, sizeof(char));
    AES_CBC_decrypt_File(test_buff, test_file);
    printf("testbuff decrypt [%d][%s]\r\n",(int)strlen(test_buff), test_buff);
    AES_CBC_encrypt_File(test_buff, test_file);
    free(test_buff);
    test_buff1 = calloc(2500, sizeof(char));
    AES_CBC_decrypt_File(test_buff1, test_file);
    printf("testbuff1 decrypt [%d][%s]\r\n",(int)strlen(test_buff1), test_buff1);
    AES_CBC_encrypt_File(test_buff1, test_file);
    free(test_buff1);
    test_buff2 = calloc(2500, sizeof(char));
    AES_CBC_decrypt_File(test_buff2, test_file);
    printf("testbuff2 decrypt [%d][%s]\r\n",(int)strlen(test_buff2), test_buff1);
    free(test_buff2);
    #if 0
    //encorder
    EncBuff = calloc((size +11), sizeof(char));
    //AES_ECB_Encrypt(buffer, Key, EncBuff, size);
    //초기화 벡터값과 공개키로 RoundKey 생성 - 이곳에서 시간 소모가 가장 큼
    AES_init_ctx_iv(&ctx, key, iv);
    
    //실제 암호화 함수
    //aes 구조체 포인터, 원본 데이터, 결과를 저장할 변수, 데이터 길이
    //암호화된 데이터는 inConv 변수를 통해 받을 수 있다. 
    
    AES_CBC_encrypt_bufferEx(&ctx, buffer, EncBuff, (size));

    printf("\nEncorded: ");
    for (i=0; i<(size); i++) printf(" %02X", EncBuff[i]&0x000000FF);
    fpOut = fopen(argv[2],"w");
    fwrite(EncBuff,size+10 , 1, fpOut);
    fclose(fpOut);
    free(EncBuff);
    fclose(fp);
    free(buffer);

    //decorder
    fpIn = fopen(argv[2],"r");
    //file size check
    fseek(fpIn, 0, SEEK_END);
    size = ftell(fpIn);
    printf("file size = %d \r\n", size);
    //file read data
    inbuffer = calloc(size + 11, sizeof(char));
    fseek(fpIn, 0, SEEK_SET);
    count = fread(inbuffer, size, 1, fpIn);
    DecBuff = calloc(size + 11, sizeof(char));
    printf("\nread data : \n");
    for(i=0; i<size; i++) printf("%02X ", inbuffer[i]&0x000000FF);
    //AES_ECB_Decrypt(inbuffer, Key, DecBuff, size);
    //초기화 벡터값과 공개키로 RoundKey 생성 - 이곳에서 시간 소모가 가장 큼
    AES_init_ctx_iv(&ctx1, key, iv1);
    
    //  실제 암호 해독 함수 
    //  aes 구조체 포인터, 암호 데이터, 데이터 길이
    //  해독된 데이터는 in 변수를 통해 얻을 수 있다.
     
    AES_CBC_decrypt_buffer(&ctx1, inbuffer, size);
    printf("\nDecorded:  ");
    for(i=0; i<size; i++) printf("%02X ", inbuffer[i]&0x000000FF);
    printf("\r\nstart read buffer============================\r\n");
    printf("%s", inbuffer);
    printf("\r\nend read buffer============================\r\n");
    fclose(fpIn);
    free(inbuffer);
    free(DecBuff);
    #endif
    return 0;
}