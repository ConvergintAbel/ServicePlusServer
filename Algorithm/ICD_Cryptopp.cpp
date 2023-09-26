#include "stdafx.h"

#define CRYPTOPP_DEFAULT_NO_DLL
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "Cryptopp/dll.h"
#include "Cryptopp/cryptlib.h"

#ifdef _DEBUG
#pragma comment(lib, "Debug\\cryptlib.lib")
#else
#pragma comment(lib, "cryptlib.lib")
#endif

#include "Cryptopp/base64.h"
#include "Cryptopp/md5.h"
#include "Cryptopp/sha.h"
#include "Cryptopp/crc.h"
#include "Cryptopp/hmac.h"
#include "Cryptopp/aes.h"

using namespace CryptoPP;

#include "ICD_Cryptopp.h"

CString CRYPTOPP_MD5(unsigned char * pInput, int nLen)
{
	if (!pInput)
		return _T("");

	if (nLen == 0)
		nLen = strlen((const char *)pInput);


	string dst;
	Weak1::MD5 md5;
	StringSource(pInput, nLen, true, new HashFilter(md5, new HexEncoder(new StringSink(dst))));

// 	MD5 md5;
// 	md5.Update(pInput, nLen);
// 
// 	unsigned char m[16];
// 	md5.Final(m);
// 
// 	for (int nIndex = 0; nIndex < 16; nIndex++)
// 	{
// 		strFormat.Format(_T("%02X"), m[nIndex]);
// 		strMD5 += strFormat;
// 	}

	return CString(dst.c_str()).MakeLower();
}

CString CRYPTOPP_MD5_File(unsigned char * pFilePath)
{
	if (!pFilePath)
		return _T("");

	FILE * pFile = NULL;
	fopen_s(&pFile, (char *)pFilePath, (const char*)_T("r+b"));
	if (!pFile)
		return _T("");

	fseek(pFile, 0, SEEK_END);
	int nLen = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	unsigned char * pDataBuf = (unsigned char *)malloc(nLen + 1);
	memset(pDataBuf, 0, nLen + 1);
	int iRead = fread(pDataBuf, sizeof(unsigned char), nLen, pFile);
	fclose(pFile);

	CString strMD5 = CRYPTOPP_MD5(pDataBuf, nLen);
	SAFE_FREE(pDataBuf);

	return strMD5;
}

CString CRYPTOPP_Base64Encode(unsigned char * pInput, int nLen)
{
	if (!pInput)
		return _T("");

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

// 	Base64Encoder encoder;
// 	encoder.Put(pInput, nLen);
//  	encoder.MessageEnd();

// 	CString strEncode = _T("");
// 	word64 size = encoder.MaxRetrievable();
// 	if (size)
// 	{
// 		unsigned char * pData = new unsigned char[size + 1];
// 		memset(pData, 0, size + 1);
// 		encoder.Get((unsigned char *)pData, size);
// 		strEncode.Format(_T("%s"), pData);
// 
// 		delete[] pData;
// 		pData = NULL;
// 
// 		strEncode.Trim(_T("\n"));
// 		strEncode.Trim(_T("\r"));
// 	}

	string dst;
	StringSource(pInput, nLen, true, new Base64Encoder(/*new HexEncoder*/(new StringSink(dst))));

	CString strResult = dst.c_str();
	strResult.Replace(_T("\n"), _T(""));
	return strResult;
}

CString CRYPTOPP_Base64Encode_File(unsigned char * pFilePath)
{
	if (!pFilePath)
		return _T("");

	FILE * pFile = NULL;
	fopen_s(&pFile, (char *)pFilePath, (const char*)_T("r+b"));
	if (!pFile)
		return _T("");

	fseek(pFile, 0, SEEK_END);
	int nLen = ftell(pFile);
	fseek(pFile, 0, SEEK_SET);

	unsigned char * pDataBuf = (unsigned char *)malloc(nLen + 1);
	memset(pDataBuf, 0, nLen + 1);
	int iRead = fread(pDataBuf, sizeof(unsigned char), nLen, pFile);
	fclose(pFile);

	CString strBase64 = CRYPTOPP_Base64Encode(pDataBuf, nLen);
	SAFE_FREE(pDataBuf);

	return strBase64;

}

int CRYPTOPP_Base64Decode(IN OUT unsigned char *& pOutData_malloc, CString str64Data)
{
	str64Data.Trim();
	if (str64Data.IsEmpty())
		return 0;

	string dst;
	StringSource((unsigned char *)str64Data.GetBuffer(0), str64Data.GetLength(), true, new Base64Decoder(/*new HexEncoder*/(new StringSink(dst))));

	int nDataSize = dst.size();
	if (nDataSize > 0)
	{
		pOutData_malloc = (unsigned char *)malloc(nDataSize + 1);
		memset(pOutData_malloc, 0, nDataSize + 1);

		memcpy_s(pOutData_malloc, nDataSize, dst.c_str(), nDataSize);
	}

	return nDataSize;
}

CString CRYPTOPP_SHA1(unsigned char * pInput, int nLen)
{
	if (!pInput)
		return _T("");

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	string dst;
	CryptoPP::SHA1 sha1;
	StringSource(pInput, nLen, true, new HashFilter(sha1, new HexEncoder(new StringSink(dst))));

	return CString(dst.c_str()).MakeLower();
}

CString CRYPTOPP_SHA256(unsigned char * pInput, int nLen)
{
	if (!pInput)
		return _T("");

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	string dst;
	CryptoPP::SHA256 sha256;
	StringSource(pInput, nLen, true, new HashFilter(sha256, new HexEncoder(new StringSink(dst))));

	return CString(dst.c_str()).MakeLower();
}

CString CRYPTOPP_CRC32(unsigned char * pInput, int nLen)
{
	if (!pInput)
		return _T("");

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	string dst;
	CryptoPP::CRC32 crc32;
	StringSource(pInput, nLen, true, new HashFilter(crc32, new HexEncoder(new StringSink(dst))));

	return CString(dst.c_str()).MakeLower();
}

CString CRYPTOPP_HMAC_SHA1(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen)
{
	if (!pInput || !pKey)
		return _T("");

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	string dst;
	CryptoPP::HMAC<CryptoPP::SHA1> hmac(pKey, nKeyLen);
	StringSource(pInput, nLen, true, new HashFilter(hmac, new HexEncoder(new StringSink(dst))));

	return CString(dst.c_str()).MakeLower();
}

CString CRYPTOPP_HMAC_SHA256(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen)
{
	if (!pInput || !pKey)
		return _T("");

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	string dst;
	CryptoPP::HMAC<CryptoPP::SHA256> hmac(pKey, nKeyLen);
	StringSource(pInput, nLen, true, new HashFilter(hmac, new HexEncoder(new StringSink(dst))));

	return CString(dst.c_str()).MakeLower();
}

//不能用CString
string CRYPTOPP_HMAC_SHA256_BIN(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen)
{
	if (!pInput || !pKey)
		return _T("");

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	string dst;
	CryptoPP::HMAC<CryptoPP::SHA256> hmac(pKey, nKeyLen);
// 	StringSource(pInput, nLen, true, new HashFilter(hmac, new HexEncoder(new StringSink(dst))));
	StringSource(pInput, nLen, true, new HashFilter(hmac, new StringSink(dst)));

// 	return CString(dst.c_str()).MakeLower();
	return dst;
}

CString CRYPTOPP_AES_ECB(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen, int nPaddingType)
{
	if (!pInput || !pKey)
		return _T("");

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nKeyLen != CryptoPP::AES::DEFAULT_KEYLENGTH && nKeyLen != CryptoPP::AES::MAX_KEYLENGTH)
 		return _T("");

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	string dst;
 	CryptoPP::AES::Encryption aesEncryption(pKey, nKeyLen);
 	CryptoPP::ECB_Mode_ExternalCipher::Encryption ecbEncryption(aesEncryption);

	StringSource(pInput, nLen, true, new StreamTransformationFilter(ecbEncryption, new HexEncoder(new StringSink(dst)), (StreamTransformationFilter::BlockPaddingScheme)nPaddingType));

	return CString(dst.c_str()).MakeLower();
}

int CRYPTOPP_AES_ECB(IN OUT unsigned char *& pOutData_malloc, unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen, int nPaddingType)
{
	if (!pInput || !pKey)
		return 0;

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nKeyLen != CryptoPP::AES::DEFAULT_KEYLENGTH && nKeyLen != CryptoPP::AES::MAX_KEYLENGTH)
		return 0;

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	string dst;
	CryptoPP::AES::Encryption aesEncryption(pKey, nKeyLen);
	CryptoPP::ECB_Mode_ExternalCipher::Encryption ecbEncryption(aesEncryption);

	StringSource(pInput, nLen, true, new StreamTransformationFilter(ecbEncryption, /*new HexEncoder*/(new StringSink(dst)), (StreamTransformationFilter::BlockPaddingScheme)nPaddingType));

	int nDataSize = dst.size();
	if (nDataSize > 0)
	{
		if ((StreamTransformationFilter::BlockPaddingScheme)nPaddingType == StreamTransformationFilter::BlockPaddingScheme::ZEROS_PADDING)
		{
			//编码最后有可能是\0
			while (dst[nDataSize - 1] == '\0')
			{
				nDataSize--;
			}
		}

		pOutData_malloc = (unsigned char *)malloc(nDataSize + 1);
		memset(pOutData_malloc, 0, nDataSize + 1);

		memcpy_s(pOutData_malloc, nDataSize, dst.c_str(), nDataSize);
	}

	return nDataSize;
}


int CRYPTOPP_AES_ECB_Decode(IN OUT unsigned char *& pOutData_malloc, unsigned char * pInput, int& nLen, unsigned char * pKey, int nKeyLen, int nPaddingType)
{
	if (!pInput || !pKey)
		return 0;

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nKeyLen != CryptoPP::AES::DEFAULT_KEYLENGTH && nKeyLen != CryptoPP::AES::MAX_KEYLENGTH)
		return 0;

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	//如果长度不是整数倍，后面补0
	unsigned char * pInput_malloc = NULL;
	if ((nLen % CryptoPP::AES::DEFAULT_KEYLENGTH) != 0)
	{
		int nNewLen = ((nLen / CryptoPP::AES::DEFAULT_KEYLENGTH) + 1) * CryptoPP::AES::DEFAULT_KEYLENGTH;
		
		pInput_malloc = (unsigned char *)malloc(nNewLen);
		memset(pInput_malloc, 0, nNewLen);
		memcpy(pInput_malloc, pInput, nLen);

		pInput = pInput_malloc;
		nLen = nNewLen;
	}

	string dst;
	CryptoPP::AES::Decryption aesDecryption(pKey, CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::ECB_Mode_ExternalCipher::Decryption ecbDecryption(aesDecryption);

	StringSource(pInput, nLen, true, new StreamTransformationFilter(ecbDecryption, /*new HexEncoder*/(new StringSink(dst)), (StreamTransformationFilter::BlockPaddingScheme)nPaddingType));
	SAFE_FREE(pInput_malloc);

	int nDataSize = dst.size();
	if (nDataSize > 0)
	{
		if ((StreamTransformationFilter::BlockPaddingScheme)nPaddingType == StreamTransformationFilter::BlockPaddingScheme::ZEROS_PADDING)
		{
			while (dst[nDataSize - 1] == '\0')
			{
				nDataSize--;
			}
		}

		pOutData_malloc = (unsigned char *)malloc(nDataSize + 1);
		memset(pOutData_malloc, 0, nDataSize + 1);

		memcpy_s(pOutData_malloc, nDataSize, dst.c_str(), nDataSize);
	}

	return nDataSize;
}

CString CRYPTOPP_AES_CBC(unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen, unsigned char * pIV, int nPaddingType)
{
	if (!pInput || !pKey || !pIV)
		return _T("");

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nKeyLen != CryptoPP::AES::DEFAULT_KEYLENGTH && nKeyLen != CryptoPP::AES::MAX_KEYLENGTH)
		return _T("");

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	int nIVLen = strlen((const char *)pIV);
	if (nIVLen != 0 && nIVLen != 16)
		return _T("");

	string dst;
	CryptoPP::AES::Encryption aesEncryption(pKey, nKeyLen);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, pIV);

	StringSource(pInput, nLen, true, new StreamTransformationFilter(cbcEncryption, new HexEncoder(new StringSink(dst)), (StreamTransformationFilter::BlockPaddingScheme)nPaddingType));

	return CString(dst.c_str()).MakeLower();
}

int CRYPTOPP_AES_CBC(unsigned char *& pOutData_malloc, unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen, unsigned char * pIV, int nPaddingType)
{
	if (!pInput || !pKey || !pIV)
		return 0;

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nKeyLen != CryptoPP::AES::DEFAULT_KEYLENGTH && nKeyLen != CryptoPP::AES::MAX_KEYLENGTH)
		return 0;

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	int nIVLen = strlen((const char *)pIV);
	if (nIVLen != 0 && nIVLen != 16)
		return 0;

	string dst;
	CryptoPP::AES::Encryption aesEncryption(pKey, nKeyLen);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, pIV);

	StringSource(pInput, nLen, true, new StreamTransformationFilter(cbcEncryption, /*new HexEncoder*/(new StringSink(dst)), (StreamTransformationFilter::BlockPaddingScheme)nPaddingType));

	int nDataSize = dst.size();
	if (nDataSize > 0)
	{
		if ((StreamTransformationFilter::BlockPaddingScheme)nPaddingType == StreamTransformationFilter::BlockPaddingScheme::ZEROS_PADDING)
		{
			while (dst[nDataSize - 1] == '\0')
			{
				nDataSize--;
			}
		}

		pOutData_malloc = (unsigned char *)malloc(nDataSize + 1);
		memset(pOutData_malloc, 0, nDataSize + 1);

		memcpy_s(pOutData_malloc, nDataSize, dst.c_str(), nDataSize);
	}

	return nDataSize;
}

int  CRYPTOPP_AES_CBC_Decode(unsigned char *& pOutData_malloc, unsigned char * pInput, int nLen, unsigned char * pKey, int nKeyLen, unsigned char * pIV, int nPaddingType)
{
	if (!pInput || !pKey || !pIV)
		return 0;

	if (nKeyLen == 0)
		nKeyLen = strlen((const char *)pKey);

	if (nKeyLen != CryptoPP::AES::DEFAULT_KEYLENGTH && nKeyLen != CryptoPP::AES::MAX_KEYLENGTH)
		return 0;

	if (nLen == 0)
		nLen = strlen((const char *)pInput);

	if ((nLen % CryptoPP::AES::DEFAULT_KEYLENGTH) != 0)
		return 0;

	int nIVLen = strlen((const char *)pIV);
	if (nIVLen != 0 && nIVLen != 16)
		return 0;

	string dst;
	CryptoPP::AES::Decryption aesDecryption(pKey, nKeyLen);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, pIV);

	StringSource(pInput, nLen, true, new StreamTransformationFilter(cbcDecryption, /*new HexEncoder*/(new StringSink(dst)), (StreamTransformationFilter::BlockPaddingScheme)nPaddingType));

	int nDataSize = dst.size();
	if (nDataSize > 0)
	{
		if ((StreamTransformationFilter::BlockPaddingScheme)nPaddingType == StreamTransformationFilter::BlockPaddingScheme::ZEROS_PADDING)
		{
			while (dst[nDataSize - 1] == '\0')
			{
				nDataSize--;
			}
		}

		pOutData_malloc = (unsigned char *)malloc(nDataSize + 1);
		memset(pOutData_malloc, 0, nDataSize + 1);

		memcpy_s(pOutData_malloc, nDataSize, dst.c_str(), nDataSize);
	}

	return nDataSize;
}

CString ICD_CalcEncrypt_AES_Base(CString strJson, CString strKey)
{
	strJson.Trim();
	strKey.Trim();
	if (strJson.IsEmpty() || strKey.IsEmpty())
		return _T("");

	if (strKey.GetLength() != CryptoPP::AES::DEFAULT_KEYLENGTH && strKey.GetLength() != CryptoPP::AES::MAX_KEYLENGTH)
		return _T("");

	unsigned char * pOutData_malloc = NULL;
	int nAESSize = CRYPTOPP_AES_ECB(pOutData_malloc, (unsigned char *)strJson.GetBuffer(0), strJson.GetLength(), (unsigned char *)strKey.GetBuffer(0), strKey.GetLength());
	if (!pOutData_malloc)
		return _T("");

	CString strBase = CRYPTOPP_Base64Encode(pOutData_malloc, nAESSize);
	SAFE_FREE(pOutData_malloc);

	return strBase;
}

CString ICD_CalcEncrypt_AES_Base_Decode(CString strBase64, CString strKey)
{
	strBase64.Trim();
	strKey.Trim();
	if (strBase64.IsEmpty() || strKey.IsEmpty())
		return _T("");

	if (strKey.GetLength() != CryptoPP::AES::DEFAULT_KEYLENGTH && strKey.GetLength() != CryptoPP::AES::MAX_KEYLENGTH)
		return _T("");

	unsigned char * pBase_malloc = NULL;
	int nBase64 = CRYPTOPP_Base64Decode(pBase_malloc, strBase64);
	if (!pBase_malloc)
		return _T("");

	unsigned char * pOutData_malloc = NULL;
	int nAESSize = CRYPTOPP_AES_ECB_Decode(pOutData_malloc, pBase_malloc, nBase64, (unsigned char *)strKey.GetBuffer(0), strKey.GetLength());
	SAFE_FREE(pBase_malloc);

	CString strAES = _T("");
	if (pOutData_malloc)
		strAES.Format(_T("%s"), pOutData_malloc);

	SAFE_FREE(pOutData_malloc);

	return strAES;
}
/************************************************************************
* @function		UTF8ToUnicode
* @brief		UTF8 to Unicode
* @param		[IN]UTF8
* @return		Unicode
* @author		Abel.wang@icdsecurity.com
* @date			2018-11-18
* @version		2.0
************************************************************************/
CStringW Common_Convert_UTF8_To_Unicode(CString strUTF8)
{
	//UTF8----UNICODE
	char* szU8 = strUTF8.GetBuffer(0);

	//预转换，得到所需空间的大小
	int wcsLen = ::MultiByteToWideChar(CP_UTF8, NULL, szU8, strlen(szU8), NULL, 0);
	//分配空间要给'\0'留个空间，MultiByteToWideChar不会给'\0'空间
	wchar_t* wszString = new wchar_t[wcsLen + 1];
	//转换
	::MultiByteToWideChar(CP_UTF8, NULL, szU8, strlen(szU8), wszString, wcsLen);
	//最后加上'\0'
	wszString[wcsLen] = '\0';
	strUTF8.ReleaseBuffer();

	CStringW wstr_Unicode(wszString);
	SAFE_DELETE_ARRAY(wszString);

	return wstr_Unicode;
}

/************************************************************************
* @function		UnicodeToUTF8
* @brief		Unicode to UTF8
* @param		[IN]Unicode
* @return		UTF8
* @author		Abel.wang@icdsecurity.com
* @date			2018-11-18
* @version		2.0
************************************************************************/
CString Common_Convert_Unicode_To_UTF8(CStringW wstr_Unicode)
{
	wchar_t* wch_Unicode = wstr_Unicode.GetBuffer(0);

	int len = WideCharToMultiByte(CP_UTF8, 0, wch_Unicode, -1, NULL, 0, NULL, NULL);
	char *szUtf8 = (char*)malloc(len + 1);
	memset(szUtf8, 0, len + 1);
	::WideCharToMultiByte(CP_UTF8, 0, wch_Unicode, -1, szUtf8, len, NULL, NULL);
	wstr_Unicode.ReleaseBuffer();

	CString strUTF8(szUtf8);
	SAFE_FREE(szUtf8);

	return strUTF8;
}

void Common_ICD_MakeLower_UTF8(IN OUT CString& utf_strValue, IN BOOL bUpper)
{
	CStringW wstr_Value = Common_Convert_UTF8_To_Unicode(utf_strValue);
	wstr_Value.Trim();
	if (bUpper)
		wstr_Value.MakeUpper();
	else
		wstr_Value.MakeLower();
	utf_strValue = Common_Convert_Unicode_To_UTF8(wstr_Value);
}

int Common_ICD_StrToHex(CString mp_strText, unsigned char * mp_uchData)
{
	mp_strText.Remove(' ');
	Common_ICD_MakeLower_UTF8(mp_strText, TRUE);
	int iLength = mp_strText.GetLength();
	if (iLength < 2)
	{
		mp_uchData[0] = (unsigned char)atoi(mp_strText);
		return 1;
	}

	int iRetLength = 0;
	unsigned int n = 0;
	for (int i = 0; i < iLength; i += 2)
	{
		sscanf_s(mp_strText.Mid(i, 2), _T("%02X"), &n);
		mp_uchData[iRetLength++] = n;
	}
	return iRetLength;
}


CString ICD_CalcEncrypt_AES_String_Decode(CString strAesString, CString strKey)
{
	strAesString.Trim();
	strKey.Trim();
	if (strAesString.IsEmpty() || strKey.IsEmpty())
		return _T("");

	if (strKey.GetLength() != CryptoPP::AES::DEFAULT_KEYLENGTH && strKey.GetLength() != CryptoPP::AES::MAX_KEYLENGTH)
		return _T("");

	int nRetLen = strAesString.GetLength() / 2;
	unsigned char * pchData = (unsigned char *)malloc(nRetLen + 1);
	memset(pchData, 0, nRetLen + 1);
	Common_ICD_StrToHex(strAesString, (unsigned char *)pchData);

	unsigned char * pOutData_malloc = NULL;
	int nAESSize = CRYPTOPP_AES_ECB_Decode(pOutData_malloc, pchData, nRetLen, (unsigned char *)strKey.GetBuffer(0), strKey.GetLength());
	SAFE_FREE(pchData);

	CString strAES = _T("");
	if (pOutData_malloc)
		strAES.Format(_T("%s"), pOutData_malloc);

	SAFE_FREE(pOutData_malloc);

	return strAES;

}


CString ICD_CheckSign(CString strBody, CString strAppId, CString strAppSecret, BOOL bEncrpt)
{
	time_t  tt = time(NULL);
	CString strTimeStamp = "";
	strTimeStamp.Format(_T("%I64d"), tt);

	CString str2Encrypt = strBody + _T(".") + strAppId + _T(".") + strTimeStamp + _T(".") + strAppSecret;
	CString strSign = CRYPTOPP_SHA256((unsigned char *)str2Encrypt.GetBuffer(0));

	CString strCopy = _T("");
	strCopy.Format(_T("_appid=%s&_timestamp=%s&_sign=%s"), strAppId, strTimeStamp, strSign);
	if (!bEncrpt)
		strCopy += _T("&_plaintext=1");

	return strCopy;
}
