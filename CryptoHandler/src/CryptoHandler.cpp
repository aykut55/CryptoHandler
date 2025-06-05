#include "CryptoHandler.h"
#include <iostream>

namespace 
{
    const std::map<ALG_ID, CCryptoHandler::AlgorithmInfo> SUPPORTED_ALGORITHMS = 
    {
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

CCryptoHandler::CCryptoHandler() 
    : m_isRunning(false)
{
    m_supportedAlgorithms = SUPPORTED_ALGORITHMS;

    IsStartTimerCalled = false;
    IsStopTimerCalled = false;
}

bool CCryptoHandler::IsRunning() const
{
    return m_isRunning;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
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

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::vector<BYTE>& encryptedOutput, const std::string& password)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return EncryptBuffer(algId, input, encryptedOutput, password, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::DecryptBuffer(ALG_ID algId, const std::vector<BYTE>& encryptedInput, std::vector<BYTE>& decryptedOutput, const std::string& password)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return DecryptBuffer(algId, encryptedInput, decryptedOutput, password, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::HashBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::string& outputHash)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return HashBuffer(algId, input, outputHash, isRunning, elapsedTimeMSec);
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::vector<BYTE>& encryptedOutput, const std::string& password, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    m_isRunning = true;

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    HCRYPTKEY hKey = GenerateKey(algId, hProv, password);
    if (!hKey) {
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    DWORD inputLen = static_cast<DWORD>(input.size());
    DWORD encryptedLen = inputLen;

    // Gerekli buffer boyutunu öğren
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &encryptedLen, 0)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    encryptedOutput.resize(encryptedLen);
    memcpy(encryptedOutput.data(), input.data(), inputLen);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedOutput.data(), &inputLen, encryptedLen)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    m_isRunning = false;

    return encryptedLen;
}

int CCryptoHandler::DecryptBuffer(ALG_ID algId, const std::vector<BYTE>& encryptedInput, std::vector<BYTE>& decryptedOutput, const std::string& password, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    m_isRunning = true;

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    HCRYPTKEY hKey = GenerateKey(algId, hProv, password);
    if (!hKey) {
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    std::vector<BYTE> buffer(encryptedInput);
    DWORD bufferLen = static_cast<DWORD>(buffer.size());

    if (!CryptDecrypt(hKey, 0, TRUE, 0, buffer.data(), &bufferLen)) {
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    buffer.resize(bufferLen);
    decryptedOutput = std::move(buffer);

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    m_isRunning = false;

    return bufferLen;
}

int CCryptoHandler::HashBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::string& outputHash, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    m_isRunning = true;

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    HCRYPTHASH hHash = 0;
    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    if (!CryptHashData(hHash, input.data(), static_cast<DWORD>(input.size()), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    DWORD hashLen = 0;
    DWORD hashLenSize = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &hashLenSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    std::vector<BYTE> hashValue(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue.data(), &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        isRunning = false;
        m_isRunning = false;
        return -1;
    }

    std::ostringstream oss;
    for (BYTE b : hashValue) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    outputHash = oss.str();

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    m_isRunning = false;

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptBufferWithCallback(ALG_ID algId, const std::string& password, const std::vector<BYTE>& input, 
    std::vector<BYTE>& encryptedOutput, bool* pIsStopRequested, bool* pIsRunning, long long* pElapsedTimeMSec, int* pErrorCode,
    StartCallback start, ProgressCallback progress, CompletionCallback completion, ErrorCallback error)
{
    auto startTime = std::chrono::steady_clock::now();

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    if (pIsRunning) *pIsRunning = true;

    if (pErrorCode) *pErrorCode = CryptoResult::Success;

    if (start) start();

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -1;
        if (error) error(-1);
        return -1;
    }

    HCRYPTKEY hKey = GenerateKey(algId, hProv, password);
    if (!hKey) {
        CryptReleaseContext(hProv, 0);
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -2;
        if (error) error(-2);
        return -2;
    }

    const size_t chunkSize = 4096;
    size_t totalInputSize = input.size();
    size_t totalProcessed = 0;

    std::vector<BYTE> buffer(chunkSize + 64); // padding için fazladan alan
    encryptedOutput.clear();

    while (totalProcessed < totalInputSize) {
        DWORD thisChunkSize = static_cast<DWORD>(std::min(chunkSize, totalInputSize - totalProcessed));
        DWORD encryptedChunkSize = thisChunkSize;

        memcpy(buffer.data(), input.data() + totalProcessed, thisChunkSize);
        BOOL isFinal = (totalProcessed + thisChunkSize >= totalInputSize) ? TRUE : FALSE;

        DWORD bufferSize = thisChunkSize;
        if (!CryptEncrypt(hKey, 0, isFinal, 0, nullptr, &bufferSize, static_cast<DWORD>(buffer.size()))) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            if (pIsRunning) *pIsRunning = false;
            if (pErrorCode) *pErrorCode = -3;
            if (error) error(-3);
            return -3;
        }

        encryptedChunkSize = thisChunkSize;
        if (!CryptEncrypt(hKey, 0, isFinal, 0, buffer.data(), &encryptedChunkSize, static_cast<DWORD>(buffer.size()))) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            if (pIsRunning) *pIsRunning = false;
            if (pErrorCode) *pErrorCode = -4;
            if (error) error(-4);
            return -4;
        }

        encryptedOutput.insert(encryptedOutput.end(), buffer.begin(), buffer.begin() + encryptedChunkSize);
        totalProcessed += thisChunkSize;

        if (progress) progress(totalProcessed, totalInputSize);

        if (pIsStopRequested && *pIsStopRequested) break;
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    if (pIsStopRequested && *pIsStopRequested) {
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -5;
        if (completion) completion(-5);
        return -5;
    }

    if (pIsRunning) *pIsRunning = false;

    if (pErrorCode) *pErrorCode = CryptoResult::Success;

    if (completion) completion(CryptoResult::Success);

    return CryptoResult::Success;
}

int CCryptoHandler::DecryptBufferWithCallback(ALG_ID algId, const std::string& password, const std::vector<BYTE>& encryptedInput, std::vector<BYTE>& decryptedOutput, bool* pIsStopRequested, bool* pIsRunning, long long* pElapsedTimeMSec, int* pErrorCode, StartCallback start, ProgressCallback progress, CompletionCallback completion, ErrorCallback error)
{
    auto startTime = std::chrono::steady_clock::now();

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    if (pIsRunning) *pIsRunning = true;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (start) start();

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -1;
        if (error) error(-1);
        return -1;
    }

    HCRYPTKEY hKey = GenerateKey(algId, hProv, password);
    if (!hKey) {
        CryptReleaseContext(hProv, 0);
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -2;
        if (error) error(-2);
        return -2;
    }

    const size_t chunkSize = 4096;
    size_t totalInputSize = encryptedInput.size();
    size_t totalProcessed = 0;

    std::vector<BYTE> buffer(chunkSize + 64); // padding için
    decryptedOutput.clear();

    while (totalProcessed < totalInputSize) {
        size_t remaining = totalInputSize - totalProcessed;
        DWORD thisChunkSize = static_cast<DWORD>(remaining < chunkSize ? remaining : chunkSize);
        DWORD decryptedChunkSize = thisChunkSize;

        memcpy(buffer.data(), encryptedInput.data() + totalProcessed, thisChunkSize);

        BOOL isFinal = (totalProcessed + thisChunkSize >= totalInputSize) ? TRUE : FALSE;

        if (!CryptDecrypt(hKey, 0, isFinal, 0, buffer.data(), &decryptedChunkSize)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            if (pIsRunning) *pIsRunning = false;
            if (pErrorCode) *pErrorCode = -3;
            if (error) error(-3);
            return -3;
        }

        decryptedOutput.insert(decryptedOutput.end(), buffer.begin(), buffer.begin() + decryptedChunkSize);
        totalProcessed += thisChunkSize;

        if (progress) progress(totalProcessed, totalInputSize);

        if (pIsStopRequested && *pIsStopRequested) break;
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    if (pIsStopRequested && *pIsStopRequested) {
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -4;
        if (completion) completion(-4);
        return -4;
    }

    if (pIsRunning) *pIsRunning = false;

    if (pErrorCode) *pErrorCode = CryptoResult::Success;

    if (completion) completion(CryptoResult::Success);

    return CryptoResult::Success;
}

int CCryptoHandler::HashBufferWithCallback(ALG_ID algId, const std::vector<BYTE>& input, std::vector<BYTE>& outputHashBytes, std::string& outputHash, bool* pIsStopRequested, bool* pIsRunning, long long* pElapsedTimeMSec, int* pErrorCode, StartCallback start, ProgressCallback progress, CompletionCallback completion, ErrorCallback error)
{
    auto startTime = std::chrono::steady_clock::now();

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    if (pIsRunning) *pIsRunning = true;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (start) start();

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -1;
        if (error) error(-1);
        return -1;
    }

    HCRYPTHASH hHash;
    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -2;
        if (error) error(-2);
        return -2;
    }

    const size_t chunkSize = 4096;
    size_t totalInputSize = input.size();
    size_t totalProcessed = 0;

    while (totalProcessed < totalInputSize) {
        size_t remaining = totalInputSize - totalProcessed;
        DWORD thisChunkSize = static_cast<DWORD>((remaining < chunkSize) ? remaining : chunkSize);

        if (!CryptHashData(hHash, input.data() + totalProcessed, thisChunkSize, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            if (pIsRunning) *pIsRunning = false;
            if (pErrorCode) *pErrorCode = -3;
            if (error) error(-3);
            return -3;
        }

        totalProcessed += thisChunkSize;
        if (progress) progress(totalProcessed, totalInputSize);

        if (pIsStopRequested && *pIsStopRequested) break;
    }

    if (pIsStopRequested && *pIsStopRequested) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -6;
        if (completion) completion(-6);
        return -6;
    }

    // Hash boyutu al
    DWORD hashLen = 0;
    DWORD lenSize = sizeof(DWORD);
    if (!CryptGetHashParam(hHash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hashLen), &lenSize, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -4;
        if (error) error(-4);
        return -4;
    }

    outputHashBytes.resize(hashLen);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, outputHashBytes.data(), &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -5;
        if (error) error(-5);
        return -5;
    }

    // Hash verisini hex string'e çevir
    std::ostringstream oss;
    for (BYTE b : outputHashBytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    outputHash = oss.str();

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    if (pIsRunning) *pIsRunning = false;

    if (pErrorCode) *pErrorCode = CryptoResult::Success;

    if (completion) completion(CryptoResult::Success);

    return CryptoResult::Success;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return EncryptString(algId, password, input, output, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::DecryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return DecryptString(algId, password, input, output, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::HashString(ALG_ID algId, const std::string& input, std::string& outputHash)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return HashString(algId, input, outputHash, isRunning, elapsedTimeMSec);
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::vector<BYTE> inputBuffer(input.begin(), input.end());
    std::vector<BYTE> encryptedBuffer;

    int result = EncryptBuffer(algId, inputBuffer, encryptedBuffer, password);
    if (result < 0) {
        isRunning = false;
        return result;
    }

    // Base64Encode işlemi BYTE vector üzerinden yapıldı
    output = Base64Encode(encryptedBuffer);

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

int CCryptoHandler::DecryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::vector<BYTE> encryptedBuffer = Base64Decode(input);
    if (encryptedBuffer.empty()) {
        isRunning = false;
        return -1;
    }

    std::vector<BYTE> decryptedBuffer;

    int result = DecryptBuffer(algId, encryptedBuffer, decryptedBuffer, password);
    if (result < 0) {
        isRunning = false;
        return result;
    }

    output.assign(decryptedBuffer.begin(), decryptedBuffer.end());

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

int CCryptoHandler::HashString(ALG_ID algId, const std::string& input, std::string& outputHash, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::vector<BYTE> inputBuffer(input.begin(), input.end());

    int result = HashBuffer(algId, inputBuffer, outputHash);
    if (result < 0) {
        isRunning = false;
        return result;
    }

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return EncryptFile(algId, inputFile, outputFile, password, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::DecryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return DecryptFile(algId, inputFile, outputFile, password, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::HashFile(ALG_ID algId, const std::string& inputFile, std::string& outputHash)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return HashFile(algId, inputFile, outputHash, isRunning, elapsedTimeMSec);
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::ifstream in(inputFile, std::ios::binary);
    if (!in) {
        isRunning = false;
        return -1;
    }

    std::vector<BYTE> inputBuffer((std::istreambuf_iterator<char>(in)), {});
    in.close();

    std::vector<BYTE> encryptedBuffer;
    int result = EncryptBuffer(algId, inputBuffer, encryptedBuffer, password);
    if (result < 0) {
        isRunning = false;
        return result;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        isRunning = false;
        return -1;
    }

    out.write(reinterpret_cast<const char*>(encryptedBuffer.data()), encryptedBuffer.size());
    out.close();

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

int CCryptoHandler::DecryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::ifstream in(inputFile, std::ios::binary);
    if (!in) {
        isRunning = false;
        return -1;
    }

    std::vector<BYTE> encryptedBuffer((std::istreambuf_iterator<char>(in)), {});
    in.close();

    std::vector<BYTE> decryptedBuffer;
    int result = DecryptBuffer(algId, encryptedBuffer, decryptedBuffer, password);
    if (result < 0) {
        isRunning = false;
        return result;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        isRunning = false;
        return -1;
    }

    out.write(reinterpret_cast<const char*>(decryptedBuffer.data()), decryptedBuffer.size());
    out.close();

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

int CCryptoHandler::HashFile(ALG_ID algId, const std::string& inputFile, std::string& outputHash, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::ifstream in(inputFile, std::ios::binary);
    if (!in) {
        isRunning = false;
        return -1;
    }

    std::vector<BYTE> inputBuffer((std::istreambuf_iterator<char>(in)), {});
    in.close();

    int result = HashBuffer(algId, inputBuffer, outputHash);
    if (result < 0) {
        isRunning = false;
        return result;
    }

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return EncryptFileWithCallback(algId, inputFile, outputFile, password, NULL, NULL, NULL, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::DecryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return DecryptFileWithCallback(algId, inputFile, outputFile, password, NULL, NULL, NULL, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::HashFileWithCallback(ALG_ID algId, const std::string& inputFile, std::string& outputHash)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return HashFileWithCallback(algId, inputFile, outputHash, NULL, NULL, NULL, isRunning, elapsedTimeMSec);
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
    StartCallback start, ProgressCallback progress, CompletionCallback completion)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return EncryptFileWithCallback(algId, inputFile, outputFile, password, start, progress, completion, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::DecryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
    StartCallback start, ProgressCallback progress, CompletionCallback completion)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return DecryptFileWithCallback(algId, inputFile, outputFile, password, start, progress, completion, isRunning, elapsedTimeMSec);
}

int CCryptoHandler::HashFileWithCallback(ALG_ID algId, const std::string& inputFile, std::string& outputHash,
    StartCallback start, ProgressCallback progress, CompletionCallback completion)
{
    bool isRunning = false; long long elapsedTimeMSec = 0;
    return HashFileWithCallback(algId, inputFile, outputHash, start, progress, completion, isRunning, elapsedTimeMSec);
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
    StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    if (start) start();

    std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
    if (!in) {
        if (completion) completion(-1);
        isRunning = false;
        return -1;
    }

    size_t fileSize = in.tellg();
    in.seekg(0);

    const size_t chunkSize = 4096;
    std::vector<BYTE> inputBuffer;
    inputBuffer.reserve(fileSize);

    size_t totalRead = 0;
    BYTE buffer[chunkSize];

    while (in) {
        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
        in.read(reinterpret_cast<char*>(buffer), chunkSize);
        size_t bytesRead = in.gcount();
        totalRead += bytesRead;
        inputBuffer.insert(inputBuffer.end(), buffer, buffer + bytesRead);
        if (progress) progress(totalRead, fileSize);
    }

    in.close();

    std::vector<BYTE> encryptedBuffer;
    int result = EncryptBuffer(algId, inputBuffer, encryptedBuffer, password);
    if (result < 0) {
        if (completion) completion(result);
        isRunning = false;
        return -2;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        if (completion) completion(-1);
        isRunning = false;
        return -3;
    }

    out.write(reinterpret_cast<const char*>(encryptedBuffer.data()), encryptedBuffer.size());
    out.close();

    if (completion) completion(0);

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

int CCryptoHandler::DecryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
    StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    if (start) start();

    std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
    if (!in) {
        if (completion) completion(-1);
        isRunning = false;
        return -1;
    }

    size_t fileSize = in.tellg();
    in.seekg(0);

    const size_t chunkSize = 4096;
    std::vector<BYTE> encryptedBuffer;
    encryptedBuffer.reserve(fileSize);

    size_t totalRead = 0;
    BYTE buffer[chunkSize];

    while (in) {
        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
        in.read(reinterpret_cast<char*>(buffer), chunkSize);
        size_t bytesRead = in.gcount();
        totalRead += bytesRead;
        encryptedBuffer.insert(encryptedBuffer.end(), buffer, buffer + bytesRead);
        if (progress) progress(totalRead, fileSize);
    }

    in.close();

    std::vector<BYTE> decryptedBuffer;
    int result = DecryptBuffer(algId, encryptedBuffer, decryptedBuffer, password);
    if (result < 0) {
        if (completion) completion(result);
        isRunning = false;
        return -2;
    }

    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        if (completion) completion(-1);
        isRunning = false;
        return -3;
    }

    out.write(reinterpret_cast<const char*>(decryptedBuffer.data()), decryptedBuffer.size());
    out.close();

    if (completion) completion(0);

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

int CCryptoHandler::HashFileWithCallback(ALG_ID algId, const std::string& inputFile, std::string& outputHash,
    StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    if (start) start();

    std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
    if (!in) {
        if (completion) completion(-1);
        isRunning = false;
        return -1;
    }

    size_t fileSize = in.tellg();
    in.seekg(0);

    const size_t chunkSize = 4096;
    std::vector<BYTE> inputBuffer;
    inputBuffer.reserve(fileSize);

    size_t totalRead = 0;
    BYTE buffer[chunkSize];

    while (in) {
        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
        in.read(reinterpret_cast<char*>(buffer), chunkSize);
        size_t bytesRead = in.gcount();
        totalRead += bytesRead;
        inputBuffer.insert(inputBuffer.end(), buffer, buffer + bytesRead);
        if (progress) progress(totalRead, fileSize);
    }

    in.close();

    int result = HashBuffer(algId, inputBuffer, outputHash);
    if (completion) completion(result);

    isRunning = false;

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    return 0;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
int CCryptoHandler::EncryptFileAsync(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
    StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::thread([=, &isRunning, &elapsedTimeMSec]() mutable {

        if (start) start();

        std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
        if (!in) {
            if (completion) completion(-1);
            isRunning = false;
            return;
        }

        size_t fileSize = in.tellg();
        in.seekg(0);

        const size_t chunkSize = 4096;
        std::vector<BYTE> inputBuffer;
        inputBuffer.reserve(fileSize);

        size_t totalRead = 0;
        BYTE buffer[chunkSize];

        while (in) {
            elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
            in.read(reinterpret_cast<char*>(buffer), chunkSize);
            size_t bytesRead = in.gcount();
            totalRead += bytesRead;
            inputBuffer.insert(inputBuffer.end(), buffer, buffer + bytesRead);
            if (progress) progress(totalRead, fileSize);
        }

        in.close();

        std::vector<BYTE> encryptedBuffer;
        int result = EncryptBuffer(algId, inputBuffer, encryptedBuffer, password);
        if (result < 0) {
            if (completion) completion(result);
            isRunning = false;
            return;
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            if (completion) completion(-1);
            isRunning = false;
            return;
        }

        out.write(reinterpret_cast<const char*>(encryptedBuffer.data()), encryptedBuffer.size());
        out.close();

        if (completion) completion(0);

        isRunning = false;

        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

        }).detach();

        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

        return 0;
}

int CCryptoHandler::DecryptFileAsync(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
    StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::thread([=, &isRunning, &elapsedTimeMSec]() mutable {

        if (start) start();

        std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
        if (!in) {
            if (completion) completion(-1);
            isRunning = false;
            return;
        }

        size_t fileSize = in.tellg();
        in.seekg(0);

        const size_t chunkSize = 4096;
        std::vector<BYTE> encryptedBuffer;
        encryptedBuffer.reserve(fileSize);

        size_t totalRead = 0;
        BYTE buffer[chunkSize];

        while (in) {
            elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
            in.read(reinterpret_cast<char*>(buffer), chunkSize);
            size_t bytesRead = in.gcount();
            totalRead += bytesRead;
            encryptedBuffer.insert(encryptedBuffer.end(), buffer, buffer + bytesRead);
            if (progress) progress(totalRead, fileSize);
        }

        in.close();

        std::vector<BYTE> decryptedBuffer;
        int result = DecryptBuffer(algId, encryptedBuffer, decryptedBuffer, password);
        if (result < 0) {
            if (completion) completion(result);
            isRunning = false;
            return;
        }

        std::ofstream out(outputFile, std::ios::binary);
        if (!out) {
            if (completion) completion(-1);
            isRunning = false;
            return;
        }

        out.write(reinterpret_cast<const char*>(decryptedBuffer.data()), decryptedBuffer.size());
        out.close();

        if (completion) completion(0);

        isRunning = false;

        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

        }).detach();

        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

        return 0;
}

int CCryptoHandler::HashFileAsync(ALG_ID algId, const std::string& inputFile, std::string& outputHash,
    StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec)
{
    isRunning = true; // hemen ata (main thread)

    auto startTime = std::chrono::steady_clock::now();

    elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    std::thread([=, &isRunning, &elapsedTimeMSec]() mutable {

        if (start) start();

        std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
        if (!in) {
            if (completion) completion(-1);
            isRunning = false;
            return;
        }

        size_t fileSize = in.tellg();
        in.seekg(0);

        const size_t chunkSize = 4096;
        std::vector<BYTE> inputBuffer;
        inputBuffer.reserve(fileSize);

        size_t totalRead = 0;
        BYTE buffer[chunkSize];

        while (in) {
            elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
            in.read(reinterpret_cast<char*>(buffer), chunkSize);
            size_t bytesRead = in.gcount();
            totalRead += bytesRead;
            inputBuffer.insert(inputBuffer.end(), buffer, buffer + bytesRead);
            if (progress) progress(totalRead, fileSize);
        }

        in.close();

        int result = HashBuffer(algId, inputBuffer, outputHash);

        if (completion) completion(result);

        isRunning = false;

        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

        }).detach();

        elapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

        return 0;
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
std::string CCryptoHandler::Base64Encode(const std::vector<BYTE>& input)
{
    DWORD outputLength = 0;
    if (!CryptBinaryToStringA(input.data(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &outputLength)) {
        return "";
    }

    std::string encodedString(outputLength, '\0');
    if (!CryptBinaryToStringA(input.data(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &encodedString[0], &outputLength)) {
        return "";
    }

    return encodedString;
}

std::vector<BYTE> CCryptoHandler::Base64Decode(const std::string& input)
{
    DWORD outputLength = 0;
    if (!CryptStringToBinaryA(input.c_str(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64, NULL, &outputLength, NULL, NULL)) {
        return {};
    }

    std::vector<BYTE> decodedData(outputLength);
    if (!CryptStringToBinaryA(input.c_str(), static_cast<DWORD>(input.size()), CRYPT_STRING_BASE64, decodedData.data(), &outputLength, NULL, NULL)) {
        return {};
    }

    return decodedData;
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

//--------------------------------------------------------------------------------------------------------------------------------------------------
long long CCryptoHandler::getElapsedTimeMSec(std::chrono::time_point<std::chrono::steady_clock>& m_startTime, std::chrono::time_point<std::chrono::steady_clock>& m_currentTime) const
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(m_currentTime - m_startTime).count();
}

long long CCryptoHandler::getElapsedTimeMSecUpToNow(std::chrono::time_point<std::chrono::steady_clock>& m_startTime) const
{
    auto now = std::chrono::steady_clock::now();

    return getElapsedTimeMSec(m_startTime, now);
}

//--------------------------------------------------------------------------------------------------------------------------------------------------
void CCryptoHandler::StartTimer(void)
{
    m_startTime = std::chrono::steady_clock::now();
    IsStartTimerCalled = true;
    IsStopTimerCalled = false;
}

void CCryptoHandler::StopTimer(void)
{
    m_stopTime = std::chrono::steady_clock::now();
    IsStopTimerCalled = true;
}

long long CCryptoHandler::GetElapsedTimeMsec(void)
{
    long long elapsedTimeMSec = 0;

    if (IsStartTimerCalled)
    {
        if (IsStartTimerCalled)
        {
            elapsedTimeMSec = getElapsedTimeMSec(m_startTime, m_stopTime);
        }
        else
        {
            auto now = std::chrono::steady_clock::now();
            elapsedTimeMSec = getElapsedTimeMSec(m_startTime, now);
        }
    }

    return elapsedTimeMSec;
}






int CCryptoHandler::EncryptFileWithCallback_calismadi(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
    bool* pIsStopRequested, bool* pIsRunning, long long* pElapsedTimeMSec, int* pErrorCode,
    StartCallback start, ProgressCallback progress, CompletionCallback completion, ErrorCallback error)
{
    auto startTime = std::chrono::steady_clock::now();

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    if (pIsRunning) *pIsRunning = true;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (start) start();

    // FileEnc Begin
    std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
    if (!in) {
        if (completion) completion(-1);
        if (pIsRunning) *pIsRunning = false;
        return -1;
    }

    size_t totalInputSize = static_cast<size_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    const size_t chunkSize = 4096;
    size_t totalProcessed = 0;

    std::vector<BYTE> inputBuffer(chunkSize);
    std::vector<BYTE> encryptedBuffer;

    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        if (completion) completion(-2);
        if (pIsRunning) *pIsRunning = false;
        return -2;
    }

    while (!in.eof()) {
        if (pIsStopRequested && *pIsStopRequested) break;

        in.read(reinterpret_cast<char*>(inputBuffer.data()), chunkSize);
        std::streamsize bytesRead = in.gcount();

        if (bytesRead <= 0) break;

        std::vector<BYTE> actualInput(inputBuffer.begin(), inputBuffer.begin() + bytesRead);
        encryptedBuffer.clear();

        // Local state for each chunk
        bool localIsRunning = false;
        long long localElapsed = 0;
        int localErrorCode = 0;

        int encResult = EncryptBufferWithCallback(algId, password, actualInput, encryptedBuffer,
            pIsStopRequested, &localIsRunning, &localElapsed, &localErrorCode,
            nullptr, nullptr, nullptr, nullptr); // iç callback'ler burada pas geçilir

        if (encResult != CryptoResult::Success) {
            if (error) error(encResult);
            if (completion) completion(encResult);
            if (pIsRunning) *pIsRunning = false;
            return encResult;
        }

        out.write(reinterpret_cast<const char*>(encryptedBuffer.data()), encryptedBuffer.size());
        totalProcessed += static_cast<size_t>(bytesRead);

        if (progress) progress(totalProcessed, totalInputSize);
    }
    // FileEnc End

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);

    if (pIsStopRequested && *pIsStopRequested) {
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -5;
        if (completion) completion(-5);
        return -5;
    }

    if (pIsRunning) *pIsRunning = false;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (completion) completion(CryptoResult::Success);

    return CryptoResult::Success;
}

int CCryptoHandler::DecryptFileWithCallback_calismadi(
    ALG_ID algId,
    const std::string& inputFile,
    const std::string& outputFile,
    const std::string& password,
    bool* pIsStopRequested,
    bool* pIsRunning,
    long long* pElapsedTimeMSec,
    int* pErrorCode,
    StartCallback start,
    ProgressCallback progress,
    CompletionCallback completion,
    ErrorCallback error)
{
    auto startTime = std::chrono::steady_clock::now();
    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    if (pIsRunning) *pIsRunning = true;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (start) start();

    std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
    if (!in) {
        if (completion) completion(-1);
        if (pIsRunning) *pIsRunning = false;
        return -1;
    }

    size_t totalInputSize = static_cast<size_t>(in.tellg());
    in.seekg(0, std::ios::beg);

    const size_t chunkSize = 4096;
    size_t totalProcessed = 0;

    std::vector<BYTE> inputBuffer(chunkSize + 64);
    std::vector<BYTE> decryptedBuffer;

    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        if (completion) completion(-2);
        if (pIsRunning) *pIsRunning = false;
        return -2;
    }

    while (!in.eof()) {
        if (pIsStopRequested && *pIsStopRequested) break;

        in.read(reinterpret_cast<char*>(inputBuffer.data()), chunkSize);
        std::streamsize bytesRead = in.gcount();
        if (bytesRead <= 0) break;

        std::vector<BYTE> actualInput(inputBuffer.begin(), inputBuffer.begin() + bytesRead);
        decryptedBuffer.clear();

        bool localIsRunning = false;
        long long localElapsed = 0;
        int localErrorCode = 0;

        int decResult = DecryptBufferWithCallback(
            algId, password, actualInput, decryptedBuffer,
            pIsStopRequested, &localIsRunning, &localElapsed, &localErrorCode,
            nullptr, nullptr, nullptr, nullptr);

        if (decResult != CryptoResult::Success) {
            if (error) error(decResult);
            if (completion) completion(decResult);
            if (pIsRunning) *pIsRunning = false;
            return decResult;
        }

        out.write(reinterpret_cast<const char*>(decryptedBuffer.data()), decryptedBuffer.size());
        totalProcessed += static_cast<size_t>(bytesRead);

        if (progress) progress(totalProcessed, totalInputSize);
    }

    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    if (pIsStopRequested && *pIsStopRequested) {
        if (pIsRunning) *pIsRunning = false;
        if (pErrorCode) *pErrorCode = -5;
        if (completion) completion(-5);
        return -5;
    }

    if (pIsRunning) *pIsRunning = false;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (completion) completion(CryptoResult::Success);

    return CryptoResult::Success;
}







// ==== EncryptFileStreamedWithCallback ====
int CCryptoHandler::EncryptFileStreamedWithCallback(
    ALG_ID algId,
    const std::string& inputFile,
    const std::string& outputFile,
    const std::string& password,
    bool* pIsStopRequested,
    bool* pIsRunning,
    long long* pElapsedTimeMSec,
    int* pErrorCode,
    StartCallback start,
    ProgressCallback progress,
    CompletionCallback completion,
    ErrorCallback error)
{
    auto startTime = std::chrono::steady_clock::now();
    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    if (pIsRunning) *pIsRunning = true;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (start) start();

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        if (error) error(-1);
        if (pIsRunning) *pIsRunning = false;
        return -1;
    }
    HCRYPTKEY hKey = GenerateKey(algId, hProv, password);
    if (!hKey) {
        CryptReleaseContext(hProv, 0);
        if (error) error(-2);
        if (pIsRunning) *pIsRunning = false;
        return -2;
    }

    std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
    if (!in) {
        if (error) error(-3);
        if (pIsRunning) *pIsRunning = false;
        return -3;
    }
    size_t totalSize = static_cast<size_t>(in.tellg());
    in.seekg(0);
    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        if (error) error(-4);
        if (pIsRunning) *pIsRunning = false;
        return -4;
    }

    const size_t chunkSize = 4096;
    std::vector<BYTE> buffer(chunkSize + 64);
    size_t totalProcessed = 0;

    while (!in.eof()) {
        if (pIsStopRequested && *pIsStopRequested) break;
        in.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
        DWORD bytesRead = static_cast<DWORD>(in.gcount());
        if (bytesRead == 0) break;

        BOOL isFinal = in.eof() ? TRUE : FALSE;
        DWORD bufferLen = bytesRead;
        DWORD bufferSize = static_cast<DWORD>(buffer.size());

        if (!CryptEncrypt(hKey, 0, isFinal, 0, buffer.data(), &bufferLen, bufferSize)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            if (error) error(-5);
            if (pIsRunning) *pIsRunning = false;
            return -5;
        }

        out.write(reinterpret_cast<const char*>(buffer.data()), bufferLen);
        totalProcessed += bytesRead;
        if (progress) progress(totalProcessed, totalSize);
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    if (pIsRunning) *pIsRunning = false;
    if (completion) completion(CryptoResult::Success);
    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    return CryptoResult::Success;
}

// ==== DecryptFileStreamedWithCallback ====
int CCryptoHandler::DecryptFileStreamedWithCallback(
    ALG_ID algId,
    const std::string& inputFile,
    const std::string& outputFile,
    const std::string& password,
    bool* pIsStopRequested,
    bool* pIsRunning,
    long long* pElapsedTimeMSec,
    int* pErrorCode,
    StartCallback start,
    ProgressCallback progress,
    CompletionCallback completion,
    ErrorCallback error)
{
    auto startTime = std::chrono::steady_clock::now();
    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    if (pIsRunning) *pIsRunning = true;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (start) start();

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        if (error) error(-1);
        if (pIsRunning) *pIsRunning = false;
        return -1;
    }
    HCRYPTKEY hKey = GenerateKey(algId, hProv, password);
    if (!hKey) {
        CryptReleaseContext(hProv, 0);
        if (error) error(-2);
        if (pIsRunning) *pIsRunning = false;
        return -2;
    }

    std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
    if (!in) {
        if (error) error(-3);
        if (pIsRunning) *pIsRunning = false;
        return -3;
    }
    size_t totalSize = static_cast<size_t>(in.tellg());
    in.seekg(0);
    std::ofstream out(outputFile, std::ios::binary);
    if (!out) {
        if (error) error(-4);
        if (pIsRunning) *pIsRunning = false;
        return -4;
    }

    const size_t chunkSize = 4096;
    std::vector<BYTE> buffer(chunkSize + 64);
    size_t totalProcessed = 0;

    while (!in.eof()) {
        if (pIsStopRequested && *pIsStopRequested) break;
        in.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
        DWORD bytesRead = static_cast<DWORD>(in.gcount());
        if (bytesRead == 0) break;

        BOOL isFinal = in.eof() ? TRUE : FALSE;
        DWORD bufferLen = bytesRead;

        if (!CryptDecrypt(hKey, 0, isFinal, 0, buffer.data(), &bufferLen)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            if (error) error(-5);
            if (pIsRunning) *pIsRunning = false;
            return -5;
        }

        out.write(reinterpret_cast<const char*>(buffer.data()), bufferLen);
        totalProcessed += bytesRead;
        if (progress) progress(totalProcessed, totalSize);
    }

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    if (pIsRunning) *pIsRunning = false;
    if (completion) completion(CryptoResult::Success);
    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    return CryptoResult::Success;
}


// ==== HashFileStreamedWithCallback ====
int CCryptoHandler::HashFileStreamedWithCallback(
    ALG_ID algId,
    const std::string& inputFile,
    std::string& outputHash,
    bool* pIsStopRequested,
    bool* pIsRunning,
    long long* pElapsedTimeMSec,
    int* pErrorCode,
    StartCallback start,
    ProgressCallback progress,
    CompletionCallback completion,
    ErrorCallback error)
{
    auto startTime = std::chrono::steady_clock::now();
    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    if (pIsRunning) *pIsRunning = true;
    if (pErrorCode) *pErrorCode = CryptoResult::Success;
    if (start) start();

    HCRYPTPROV hProv = GetCryptProvider();
    if (!hProv) {
        if (error) error(-1);
        if (pIsRunning) *pIsRunning = false;
        return -1;
    }
    HCRYPTHASH hHash = NULL;
    if (!CryptCreateHash(hProv, algId, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        if (error) error(-2);
        if (pIsRunning) *pIsRunning = false;
        return -2;
    }

    std::ifstream in(inputFile, std::ios::binary | std::ios::ate);
    if (!in) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        if (error) error(-3);
        if (pIsRunning) *pIsRunning = false;
        return -3;
    }
    size_t totalSize = static_cast<size_t>(in.tellg());
    in.seekg(0);

    const size_t chunkSize = 4096;
    std::vector<BYTE> buffer(chunkSize);
    size_t totalProcessed = 0;

    while (!in.eof()) {
        if (pIsStopRequested && *pIsStopRequested) break;
        in.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
        DWORD bytesRead = static_cast<DWORD>(in.gcount());
        if (bytesRead == 0) break;

        if (!CryptHashData(hHash, buffer.data(), bytesRead, 0)) {
            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);
            if (error) error(-4);
            if (pIsRunning) *pIsRunning = false;
            return -4;
        }

        totalProcessed += bytesRead;
        if (progress) progress(totalProcessed, totalSize);
    }

    BYTE hash[64];
    DWORD hashLen = sizeof(hash);
    if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        if (error) error(-5);
        if (pIsRunning) *pIsRunning = false;
        return -5;
    }

    std::ostringstream oss;
    for (DWORD i = 0; i < hashLen; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    outputHash = oss.str();

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    if (pIsRunning) *pIsRunning = false;
    if (completion) completion(CryptoResult::Success);
    if (pElapsedTimeMSec) *pElapsedTimeMSec = getElapsedTimeMSecUpToNow(startTime);
    return CryptoResult::Success;
}