#ifndef _ICD_CRYPTOPP_C_H_
#define _ICD_CRYPTOPP_C_H_

using namespace std;
#include <string>
using std::string;

#define		AES_KEY_ICD_16	_T("#ICD#AESKey@2017")

//计算字符串的MD5值(若不指定长度则由函数计算)
CString		CRYPTOPP_MD5(unsigned char * pInput, int nLen = 0);
CString		CRYPTOPP_MD5_File(unsigned char * pFilePath);

CString		CRYPTOPP_Base64Encode(unsigned char * pInput, int nLen = 0);
CString		CRYPTOPP_Base64Encode_File(unsigned char * pFilePath);
int			CRYPTOPP_Base64Decode(IN OUT unsigned char *& pOutData_malloc, CString str64Data);


CString		CRYPTOPP_SHA1(unsigned char * pInput, int nLen = 0);
CString		CRYPTOPP_SHA256(unsigned char * pInput, int nLen = 0);

CString		CRYPTOPP_CRC32(unsigned char * pInput, int nLen = 0);
CString		CRYPTOPP_HMAC_SHA1(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen);
CString		CRYPTOPP_HMAC_SHA256(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen);
string		CRYPTOPP_HMAC_SHA256_BIN(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen);

CString		CRYPTOPP_AES_ECB(unsigned char * pInput, int nLen = 0, unsigned char * pKey = (unsigned char *)AES_KEY_ICD_16, int nKeyLen = 16, int nPaddingType = 1/*StreamTransformationFilter::ZEROS_PADDING*/);
int			CRYPTOPP_AES_ECB(IN OUT unsigned char *& pOutData_malloc, unsigned char * pInput, int nLen = 0, unsigned char * pKey = (unsigned char *)AES_KEY_ICD_16, int nKeyLen = 16, int nPaddingType = 1/*StreamTransformationFilter::ZEROS_PADDING*/);
int			CRYPTOPP_AES_ECB_Decode(IN OUT unsigned char *& pOutData_malloc, unsigned char * pInput, int& nLen, unsigned char * pKey = (unsigned char *)AES_KEY_ICD_16, int nKeyLen = 16, int nPaddingType = 1/*StreamTransformationFilter::ZEROS_PADDING*/);

CString		CRYPTOPP_AES_CBC(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen, unsigned char * pIV, int nPaddingType = 1/*StreamTransformationFilter::ZEROS_PADDING*/);
int			CRYPTOPP_AES_CBC(IN OUT unsigned char *& pOutData_malloc, unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen, unsigned char * pIV, int nPaddingType = 1/*StreamTransformationFilter::ZEROS_PADDING*/);
int			CRYPTOPP_AES_CBC_Decode(IN OUT unsigned char *& pOutData_malloc, unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen, unsigned char * pIV, int nPaddingType = 1/*StreamTransformationFilter::ZEROS_PADDING*/);

CString		ICD_CalcEncrypt_AES_Base(CString strJson, CString strKey);
CString		ICD_CalcEncrypt_AES_Base_Decode(CString strBase64, CString strKey);

CString		ICD_CalcEncrypt_AES_String_Decode(CString strAesString, CString strKey = AES_KEY_ICD_16);

CString		ICD_CheckSign(CString strBody, CString strAppId, CString strAppSecret, BOOL bEncrpt = FALSE);

#endif