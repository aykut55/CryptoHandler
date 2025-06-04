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
#include <functional>

#pragma comment(lib, "crypt32.lib")

using StartCallback = std::function<void()>;
using ProgressCallback = std::function<void(size_t bytesProcessed, size_t totalBytes)>;
using CompletionCallback = std::function<void(int resultCode)>;

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

    
    // Asenkron File operations (Thread)
    int EncryptFileAsync(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);
    int DecryptFileAsync(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);
    int HashFileAsync(ALG_ID algId, const std::string& inputFile, std::string& outputHash,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);

    // Asenkron File operations
    int EncryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress,CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);
    int DecryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);
    int HashFileWithCallback(ALG_ID algId, const std::string& inputFile, std::string& outputHash, 
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);

    // File operations
    int EncryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password);
    int DecryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password);
    int HashFile(ALG_ID algId, const std::string& inputFile, std::string& outputHash);

    // String operations
    int EncryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output);
    int DecryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output);
    int HashString(ALG_ID algId, const std::string& input, std::string& outputHash);

    // Buffer operations
    int EncryptBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::vector<BYTE>& encryptedOutput, const std::string& password);
    int DecryptBuffer(ALG_ID algId, const std::vector<BYTE>& encryptedInput, std::vector<BYTE>& decryptedOutput, const std::string& password);
    int HashBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::string& outputHash);

    // Utility functions
    std::string Base64Encode(const std::vector<BYTE>& input);
    std::vector<BYTE> Base64Decode(const std::string& input);
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

    long long getElapsedTimeMSec(std::chrono::time_point<std::chrono::steady_clock>& m_startTime, std::chrono::time_point<std::chrono::steady_clock>& m_currentTime) const;
    long long getElapsedTimeMSecUpToNow(std::chrono::time_point<std::chrono::steady_clock>& m_startTime) const;
};

#endif // CryptoHandlerH
