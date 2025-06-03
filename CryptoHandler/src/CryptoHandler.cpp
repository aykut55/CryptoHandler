#include "CryptoHandler.h"

namespace {
    const std::map<ALG_ID, CCryptoHandler::AlgorithmInfo> SUPPORTED_ALGORITHMS = {
        // Encryption algorithms
        { CALG_AES_128, { CALG_AES_128, 128, 128, CCryptoHandler::ENCRYPTION, "AES-128" } },
        { CALG_AES_192, { CALG_AES_192, 192, 128, CCryptoHandler::ENCRYPTION, "AES-192" } },
        { CALG_AES_256, { CALG_AES_256, 256, 128, CCryptoHandler::ENCRYPTION, "AES-256" } },
        { CALG_DES, { CALG_DES, 56, 64, CCryptoHandler::ENCRYPTION, "DES" } },
        { CALG_3DES, { CALG_3DES, 168, 64, CCryptoHandler::ENCRYPTION, "3DES" } },
        { CALG_RC2, { CALG_RC2, 128, 64, CCryptoHandler::ENCRYPTION, "RC2" } },
        { CALG_RC4, { CALG_RC4, 128, 0, CCryptoHandler::ENCRYPTION, "RC4" } },

        // Hash algorithms
        { CALG_MD5, { CALG_MD5, 0, 0, CCryptoHandler::HASH, "MD5" } },
        { CALG_SHA1, { CALG_SHA1, 0, 0, CCryptoHandler::HASH, "SHA-1" } },
        { CALG_SHA_256, { CALG_SHA_256, 0, 0, CCryptoHandler::HASH, "SHA-256" } },
        { CALG_SHA_384, { CALG_SHA_384, 0, 0, CCryptoHandler::HASH, "SHA-384" } },
        { CALG_SHA_512, { CALG_SHA_512, 0, 0, CCryptoHandler::HASH, "SHA-512" } }
    };
}

CCryptoHandler::~CCryptoHandler()
{
}

CCryptoHandler::CCryptoHandler() : m_isRunning(false)
{
    m_supportedAlgorithms = SUPPORTED_ALGORITHMS;
}

bool CCryptoHandler::IsRunning() const
{
    return m_isRunning;
}

HCRYPTPROV CCryptoHandler::GetCryptProvider() const
{
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
        if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET)) {
            return 0;
        }
    }
    return hProv;
}

HCRYPTKEY CCryptoHandler::GenerateKey(ALG_ID algId, HCRYPTPROV hProv, const std::string& password)
{
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        return 0;
    }

    if (!CryptHashData(hHash, (const BYTE*)password.data(), (DWORD)password.size(), 0)) {
        CryptDestroyHash(hHash);
        return 0;
    }

    if (!CryptDeriveKey(hProv, algId, hHash, 0, &hKey)) {
        CryptDestroyHash(hHash);
        return 0;
    }

    CryptDestroyHash(hHash);
    return hKey;
}

bool CCryptoHandler::ValidateAlgorithm(ALG_ID algId, AlgorithmType expectedType) const
{
    auto it = m_supportedAlgorithms.find(algId);
    if (it == m_supportedAlgorithms.end()) {
        return false;
    }
    return it->second.type == expectedType;
}

// Placeholder implementations for the main methods
int CCryptoHandler::EncryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

int CCryptoHandler::DecryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

int CCryptoHandler::HashFile(ALG_ID algId, const std::string& inputFile, std::string& outputHash)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

int CCryptoHandler::EncryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

int CCryptoHandler::DecryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

int CCryptoHandler::HashString(ALG_ID algId, const std::string& input, std::string& outputHash)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

int CCryptoHandler::EncryptBuffer(ALG_ID algId, const char* input, char* output, const std::string& password)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

int CCryptoHandler::DecryptBuffer(ALG_ID algId, const char* input, char* output, const std::string& password)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

int CCryptoHandler::HashBuffer(ALG_ID algId, const char* input, std::string& outputHash)
{
    m_isRunning = true;
    // Implementation will be added in next steps
    m_isRunning = false;
    return 0;
}

std::string CCryptoHandler::Base64Encode(const std::string& input)
{
    // Implementation will be added in next steps
    return "";
}

std::string CCryptoHandler::Base64Decode(const std::string& input)
{
    // Implementation will be added in next steps
    return "";
}

std::vector<BYTE> CCryptoHandler::StringToBytes(const std::string& str)
{
    return std::vector<BYTE>(str.begin(), str.end());
}

std::string CCryptoHandler::BytesToString(const std::vector<BYTE>& bytes)
{
    return std::string(bytes.begin(), bytes.end());
}

std::string CCryptoHandler::GetLastErrorString()
{
    DWORD errorCode = GetLastError();
    if (errorCode == 0) {
        return "No error";
    }

    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        errorCode,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&messageBuffer,
        0,
        NULL
    );

    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);

    return message;
}