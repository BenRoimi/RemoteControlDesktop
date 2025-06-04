#pragma once

#include <windows.h>
#include <wincrypt.h>
#include <iostream>
#include <vector>

class Crypto
{
public:
	static void EncryptAES(const std::vector<BYTE>& plaintext, std::vector<BYTE>& ciphertext, HCRYPTKEY hKey);
	static void DecryptAES(const std::vector<BYTE>& ciphertext, std::vector<BYTE>& decryptedData, HCRYPTKEY hKey);
	static HCRYPTKEY GenerateAESKey(HCRYPTPROV hProv);

	static void EncryptRSA(const std::string& plaintext, std::vector<BYTE>& ciphertext, HCRYPTKEY hKey);
	static void DecryptRSA(const std::vector<BYTE>& ciphertext, std::string& decryptedText, HCRYPTKEY hKey);
	static HCRYPTKEY GenerateRSAKey(HCRYPTPROV hProv);
};

