#include "Crypto.h"

void Crypto::EncryptAES(const std::vector<BYTE>& plaintext, std::vector<BYTE>& ciphertext, HCRYPTKEY hKey)
{
    DWORD len = (DWORD)plaintext.size();
    DWORD bufLen = len + 16; // AES block size padding
    ciphertext.resize(bufLen);
    memcpy(ciphertext.data(), plaintext.data(), len);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, ciphertext.data(), &len, (DWORD)ciphertext.size())) {
        std::cerr << "CryptEncrypt failed" << " Error: " << GetLastError() << std::endl;
    }

    ciphertext.resize(len); // Resize to the actual encrypted data length
}

void Crypto::DecryptAES(const std::vector<BYTE>& ciphertext, std::vector<BYTE>& decryptedData, HCRYPTKEY hKey)
{
    DWORD len = (DWORD)ciphertext.size();
    decryptedData = ciphertext; // Copy ciphertext into the buffer for in-place decryption

    if (!CryptDecrypt(hKey, 0, TRUE, 0, decryptedData.data(), &len)) {
        std::cerr << "CryptDecrypt failed" << " Error: " << GetLastError() << std::endl;
    }

    decryptedData.resize(len); // Resize to actual decrypted data length
}


HCRYPTKEY Crypto::GenerateAESKey(HCRYPTPROV hProv)
{
    HCRYPTKEY hKey;

    // Generate a random AES-256 key
    if (!CryptGenKey(hProv, CALG_AES_256, CRYPT_EXPORTABLE, &hKey)) {
        std::cerr << "CryptGenKey failed" << " Error: " << GetLastError() << std::endl;
    }
    return hKey;
}

void Crypto::EncryptRSA(const std::string& plaintext, std::vector<BYTE>& ciphertext, HCRYPTKEY hKey)
{
    std::vector<BYTE> data(plaintext.begin(), plaintext.end());
    DWORD dataSize = data.size();
    DWORD bufSize = dataSize;

    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &bufSize, 0)) {
        std::cerr << "CryptEncrypt failed (size determination)" << " Error: " << GetLastError() << std::endl;
    }

    ciphertext.resize(bufSize);
    std::copy(data.begin(), data.end(), ciphertext.begin());

    if (!CryptEncrypt(hKey, 0, TRUE, 0, ciphertext.data(), &dataSize, bufSize)) {
        std::cerr << "CryptEncrypt failed" << " Error: " << GetLastError() << std::endl;
    }

    ciphertext.resize(dataSize);
}

void Crypto::DecryptRSA(const std::vector<BYTE>& ciphertext, std::string& decryptedText, HCRYPTKEY hKey)
{
    std::vector<BYTE> decryptedData(ciphertext);
    DWORD dataSize = decryptedData.size();

    if (!CryptDecrypt(hKey, 0, TRUE, 0, decryptedData.data(), &dataSize)) {
        std::cerr << "CryptDecrypt failed" << " Error: " << GetLastError() << std::endl;
    }

    decryptedData.resize(dataSize);
    decryptedText.assign(decryptedData.begin(), decryptedData.end());
}

HCRYPTKEY Crypto::GenerateRSAKey(HCRYPTPROV hProv)
{
    HCRYPTKEY hKey;
    if (!CryptGenKey(hProv, AT_KEYEXCHANGE, RSA1024BIT_KEY | CRYPT_EXPORTABLE, &hKey)) {
        std::cerr << "CryptGenKey failed" << " Error: " << GetLastError() << std::endl;
    }
    return hKey;
}
