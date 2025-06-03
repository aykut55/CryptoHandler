#ifndef CryptoHandlerH
#define CryptoHandlerH

#include <windows.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <iomanip>
#include <sstream>
#include <fstream>

#pragma comment(lib, "crypt32.lib")

class CCryptoHandler
{
public:
    virtual ~CCryptoHandler();
             CCryptoHandler();

    enum AlgorithmType { ENCRYPTION, HASH };

    struct AlgorithmInfo {
        ALG_ID algId;
        int keyLength;
        int blockSize;
        AlgorithmType type;
        std::string name;
    };

    // File operations
    int EncryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password);
    int DecryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password);
    int HashFile(ALG_ID algId, const std::string& inputFile, std::string& outputHash);

    // String operations
    int EncryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output);
    int DecryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output);
    int HashString(ALG_ID algId, const std::string& input, std::string& outputHash);

    // Buffer operations
    int EncryptBuffer(ALG_ID algId, const char* input, char* output, const std::string& password);
    int DecryptBuffer(ALG_ID algId, const char* input, char* output, const std::string& password);
    int HashBuffer(ALG_ID algId, const char* input, std::string& outputHash);

    // Utility functions
    std::string Base64Encode(const std::string& input);
    std::string Base64Decode(const std::string& input);
    std::vector<BYTE> StringToBytes(const std::string& str);
    std::string BytesToString(const std::vector<BYTE>& bytes);
    std::string GetLastErrorString();

    // Status check
    bool IsRunning() const;

protected:

private:
    std::atomic<bool> m_isRunning;
    std::map<ALG_ID, AlgorithmInfo> m_supportedAlgorithms;

    HCRYPTPROV GetCryptProvider() const;
    HCRYPTKEY GenerateKey(ALG_ID algId, HCRYPTPROV hProv, const std::string& password);
    bool ValidateAlgorithm(ALG_ID algId, AlgorithmType expectedType) const;
    std::string HashData(ALG_ID algId, const BYTE* data, DWORD dataLen);
};

#endif // CryptoHandlerH
