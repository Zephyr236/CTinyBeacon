#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include"config.h"
void PadData(unsigned char *pData, int nDataLen, int nBlockSize);
int EncryptData(unsigned char *pData, int nDataLen, unsigned char *pIv, unsigned char *pKey, unsigned char *pEncryptedData);
void CalculateHMAC(const unsigned char *pCiphertext, size_t tCiphertextLen, const char *szHmacKey, unsigned char *pResult);
int UnpadZero(unsigned char *pData, int nDataLen);
int AesDecrypt(const unsigned char *pEncryptedData, int nEncryptedDataLen, const char *szAesKey, const char *szCsFixedIV, unsigned char **ppDecryptedData);
RSA *CreateRSA(unsigned char *pKey, int nPublicToken);
int PublicKeyDecrypt(unsigned char *pEncData, int nDataLen, unsigned char *pKey, unsigned char *pDecrypted);
int PrivateKeyEncrypt(unsigned char *pData, int nDataLen, unsigned char *pKey, unsigned char *pEncrypted);
int PublicKeyEncrypt(unsigned char *pData, int nDataLen, unsigned char *pKey, unsigned char *pEncrypted);
int PrivateKeyDecrypt(unsigned char *pEncData, int nDataLen, unsigned char *pKey, unsigned char *pDecrypted);

unsigned char *EncryptAesCbc(unsigned char *pData, size_t tDataLen, unsigned char *pIv, unsigned char *pKey, size_t *ptOutLen);
unsigned char *UnpadPkcs7(unsigned char *pData, size_t tDataLen, size_t *ptUnpaddedLen);
unsigned char *PadPkcs7(unsigned char *pData, size_t tDataLen, size_t *ptPaddedLen);

#endif
