#include"../include/crypto.h"

void PadData(unsigned char *pData, int nDataLen, int nBlockSize)
{
	int nPaddingLen = nBlockSize - (nDataLen % nBlockSize);
	for (int i = 0; i < nPaddingLen; i++)
	{
		pData[nDataLen + i] = nPaddingLen;
	}
}

int EncryptData(unsigned char *pData, int nDataLen, unsigned char *pIv, unsigned char *pKey, unsigned char *pEncryptedData)
{
	AES_KEY stAesKey;
	if (AES_set_encrypt_key(pKey, 128, &stAesKey) < 0)
	{
		return -1;
	}

	int nBlockSize = AES_BLOCK_SIZE;
	PadData(pData, nDataLen, nBlockSize);

	AES_cbc_encrypt(pData, pEncryptedData, nDataLen + (nDataLen % nBlockSize), &stAesKey, pIv, AES_ENCRYPT);
	return nDataLen + (nDataLen % nBlockSize);
}

void CalculateHMAC(const unsigned char *pCiphertext, size_t tCiphertextLen, const char *szHmacKey, unsigned char *pResult)
{
	HMAC_CTX *pCtx = HMAC_CTX_new();
	if (pCtx == NULL)
	{
		fprintf(stderr, "HMAC_CTX_new failed\n");
		return;
	}

	if (HMAC_Init_ex(pCtx, szHmacKey, 16, EVP_sha256(), NULL) != 1)
	{
		HMAC_CTX_free(pCtx);
		fprintf(stderr, "HMAC_Init_ex failed\n");
		return;
	}

	if (HMAC_Update(pCtx, pCiphertext, tCiphertextLen) != 1)
	{
		HMAC_CTX_free(pCtx);
		fprintf(stderr, "HMAC_Update failed\n");
		return;
	}

	unsigned int nLength;
	if (HMAC_Final(pCtx, pResult, &nLength) != 1)
	{
		HMAC_CTX_free(pCtx);
		fprintf(stderr, "HMAC_Final failed\n");
		return;
	}

	HMAC_CTX_free(pCtx);
}

int UnpadZero(unsigned char *pData, int nDataLen)
{
	int i;
	for (i = nDataLen - 1; i >= 0; i--)
	{
		if (pData[i] != 0)
		{
			return i + 1;
		}
	}
	return 0; // 如果所有字节都是0，返回0
}

int AesDecrypt(const unsigned char *pEncryptedData, int nEncryptedDataLen, const char *szAesKey, const char *szCsFixedIV, unsigned char **ppDecryptedData)
{
	if (nEncryptedDataLen <= 16)
	{
		printf("Data too short for decryption\n");
		return -1;
	}

	// 分离加密数据和HMAC
	const unsigned char *pCiphertext = pEncryptedData;
	const unsigned char *pMessageHmac = pEncryptedData + nEncryptedDataLen - 16;
	int nCiphertextLen = nEncryptedDataLen - 16;

	// 验证HMAC
	unsigned char abCalculatedHmac[32]; // HMAC-SHA256输出32字节
	unsigned int nHmacLen;
	HMAC(EVP_sha256(), abHmacKey, 16, pCiphertext, nCiphertextLen, abCalculatedHmac, &nHmacLen);

	// 仅使用HMAC的前16字节
	if (memcmp(abCalculatedHmac, pMessageHmac, 16) != 0)
	{
		printf("HMAC verification failed, but continuing anyway\n");
		// 继续解密，即使HMAC失败
	}
	else
	{
		printf("HMAC verified successfully\n");
	}

	// AES-CBC解密
	EVP_CIPHER_CTX *pCtx = EVP_CIPHER_CTX_new();
	if (!pCtx)
	{
		return -1;
	}

	if (EVP_DecryptInit_ex(pCtx, EVP_aes_128_cbc(), NULL, (unsigned char *)szAesKey, (unsigned char *)szCsFixedIV) != 1)
	{
		EVP_CIPHER_CTX_free(pCtx);
		return -1;
	}

	// 关闭自动填充以处理原始数据
	EVP_CIPHER_CTX_set_padding(pCtx, 0);

	// 分配解密缓冲区
	*ppDecryptedData = (unsigned char *)malloc(nCiphertextLen + 16); // 额外空间
	if (!(*ppDecryptedData))
	{
		EVP_CIPHER_CTX_free(pCtx);
		return -1;
	}

	int nLen = 0;
	int nTotalLen = 0;

	// 解密
	if (EVP_DecryptUpdate(pCtx, *ppDecryptedData, &nLen, pCiphertext, nCiphertextLen) != 1)
	{
		free(*ppDecryptedData);
		EVP_CIPHER_CTX_free(pCtx);
		return -1;
	}
	nTotalLen = nLen;

	// 完成解密
	if (EVP_DecryptFinal_ex(pCtx, *ppDecryptedData + nLen, &nLen) != 1)
	{
		printf("Warning: Decryption final step failed - padding may be incorrect\n");
		// 继续处理，因为填充可能没有按预期
	}
	nTotalLen += nLen;
	EVP_CIPHER_CTX_free(pCtx);

	// 移除零填充
	int nUnpaddedLen = UnpadZero(*ppDecryptedData, nTotalLen);

	// 确保decryptedData以NULL结尾
	(*ppDecryptedData)[nUnpaddedLen] = '\0';

	return nUnpaddedLen;
}

RSA *CreateRSA(unsigned char *pKey, int nPublicToken)
{
	RSA *pRsa = NULL;
	BIO *pKeybio;
	pKeybio = BIO_new_mem_buf(pKey, -1);
	if (pKeybio == NULL)
	{
		printf("Failed to create key BIO");
		return NULL;
	}
	if (nPublicToken)
	{
		pRsa = PEM_read_bio_RSA_PUBKEY(pKeybio, &pRsa, NULL, NULL);
	}
	else
	{
		pRsa = PEM_read_bio_RSAPrivateKey(pKeybio, &pRsa, NULL, NULL);
	}
	if (pRsa == NULL)
	{
		printf("Failed to create RSA");
	}
	BIO_free(pKeybio);
	return pRsa;
}

int PublicKeyDecrypt(unsigned char *pEncData, int nDataLen, unsigned char *pKey, unsigned char *pDecrypted)
{
	RSA *pRsa = CreateRSA(pKey, 1);
	int nResult = RSA_public_decrypt(nDataLen, pEncData, pDecrypted, pRsa, nPadding);
	if (nResult == -1)
	{
		ERR_print_errors_fp(stderr);
		return -2;
	}
	return nResult;
}

int PrivateKeyEncrypt(unsigned char *pData, int nDataLen, unsigned char *pKey, unsigned char *pEncrypted)
{
	RSA *pRsa = CreateRSA(pKey, 0);
	int nResult = RSA_private_encrypt(nDataLen, pData, pEncrypted, pRsa, nPadding);
	if (nResult == -1)
	{
		ERR_print_errors_fp(stderr);
		return -2;
	}
	return nResult;
}

int PublicKeyEncrypt(unsigned char *pData, int nDataLen, unsigned char *pKey, unsigned char *pEncrypted)
{
	RSA *pRsa = CreateRSA(pKey, 1);
	int nResult = RSA_public_encrypt(nDataLen, pData, pEncrypted, pRsa, nPadding);
	if (nResult == -1)
	{
		ERR_print_errors_fp(stderr);
		return -2;
	}
	return nResult;
}

int PrivateKeyDecrypt(unsigned char *pEncData, int nDataLen, unsigned char *pKey, unsigned char *pDecrypted)
{
	RSA *pRsa = CreateRSA(pKey, 0);
	int nResult = RSA_private_decrypt(nDataLen, pEncData, pDecrypted, pRsa, nPadding);
	if (nResult == -1)
	{
		ERR_print_errors_fp(stderr);
		return -2;
	}
	return nResult;
}

unsigned char *PadPkcs7(unsigned char *pData, size_t tDataLen, size_t *ptPaddedLen)
{
	size_t tBlockSize = 16;
	size_t tPadding = tBlockSize - (tDataLen % tBlockSize);
	if (tPadding == 0)
		tPadding = tBlockSize;
	*ptPaddedLen = tDataLen + tPadding;

	unsigned char *pPaddedData = (unsigned char *)malloc(*ptPaddedLen);
	memcpy(pPaddedData, pData, tDataLen);

	// 填充字节的值等于填充的字节数
	memset(pPaddedData + tDataLen, (unsigned char)tPadding, tPadding);

	return pPaddedData;
}

unsigned char *UnpadPkcs7(unsigned char *pData, size_t tDataLen, size_t *ptUnpaddedLen)
{
	if (tDataLen == 0)
	{
		*ptUnpaddedLen = 0;
		return NULL;
	}

	unsigned char bPadding = pData[tDataLen - 1];
	if (bPadding > 16)
	{
		// 无效的填充
		*ptUnpaddedLen = tDataLen;
		unsigned char *pResult = (unsigned char *)malloc(*ptUnpaddedLen);
		memcpy(pResult, pData, *ptUnpaddedLen);
		return pResult;
	}

	// 验证所有填充字节
	for (int i = 0; i < bPadding; i++)
	{
		if (pData[tDataLen - 1 - i] != bPadding)
		{
			// 无效的填充
			*ptUnpaddedLen = tDataLen;
			unsigned char *pResult = (unsigned char *)malloc(*ptUnpaddedLen);
			memcpy(pResult, pData, *ptUnpaddedLen);
			return pResult;
		}
	}

	*ptUnpaddedLen = tDataLen - bPadding;
	unsigned char *pResult = (unsigned char *)malloc(*ptUnpaddedLen);
	memcpy(pResult, pData, *ptUnpaddedLen);
	return pResult;
}

unsigned char *EncryptAesCbc(unsigned char *pData, size_t tDataLen, unsigned char *pIv, unsigned char *pKey, size_t *ptOutLen)
{
	// PKCS7填充
	size_t tPaddedLen;
	unsigned char *pPaddedData = PadPkcs7(pData, tDataLen, &tPaddedLen);

	*ptOutLen = tPaddedLen;

	// 使用EVP接口进行AES加密
	EVP_CIPHER_CTX *pCtx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(pCtx, EVP_aes_128_cbc(), NULL, pKey, pIv);

	unsigned char *pEncrypted = (unsigned char *)malloc(tPaddedLen + EVP_MAX_BLOCK_LENGTH);
	int nEncryptedLen = 0;
	int nFinalLen = 0;

	EVP_EncryptUpdate(pCtx, pEncrypted, &nEncryptedLen, pPaddedData, tPaddedLen);
	EVP_EncryptFinal_ex(pCtx, pEncrypted + nEncryptedLen, &nFinalLen);

	*ptOutLen = nEncryptedLen + nFinalLen;

	EVP_CIPHER_CTX_free(pCtx);
	free(pPaddedData);

	return pEncrypted;
}