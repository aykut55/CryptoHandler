#ifndef CryptoHandlerH
#define CryptoHandlerH

#define NOMINMAX
#include <windows.h>

#include <wincrypt.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <chrono>
#include <thread>
#include <atomic>
#include <iomanip>   // std::hex, std::setw, std::setfill
#include <sstream>   // std::ostringstream
#include <fstream>
#include <functional>
#include <algorithm> // std::min
#include <random>

#pragma comment(lib, "crypt32.lib")

using StartCallback = std::function<void()>;
using ProgressCallback = std::function<void(size_t bytesProcessed, size_t totalBytes)>;
using CompletionCallback = std::function<void(int resultCode)>;
using ErrorCallback = std::function<void(int resultCode)>;

typedef enum CryptoResult {
    Success = 0,
    Error = -1
} CryptoResult;

class CCryptoHandler
{
public:
    virtual ~CCryptoHandler();
             CCryptoHandler();

    //--------------------------------------------------------------------------------------------------------------------------------------------------
    // Buffer operations
    int EncryptBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::vector<BYTE>& encryptedOutput, const std::string& password);
    int DecryptBuffer(ALG_ID algId, const std::vector<BYTE>& encryptedInput, std::vector<BYTE>& decryptedOutput, const std::string& password);
    int HashBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::string& outputHash);

    int EncryptBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::vector<BYTE>& encryptedOutput, const std::string& password, bool& isRunning, long long& elapsedTimeMSec);
    int DecryptBuffer(ALG_ID algId, const std::vector<BYTE>& encryptedInput, std::vector<BYTE>& decryptedOutput, const std::string& password, bool& isRunning, long long& elapsedTimeMSec);
    int HashBuffer(ALG_ID algId, const std::vector<BYTE>& input, std::string& outputHash, bool& isRunning, long long& elapsedTimeMSec);




    // isimleri Streamed li sekilde degistirilecek...
    // Eger butun input su sekilde tek seferde islenmis olsaydi: ve bu bir dongu olmadan yapiliyor olsaydi — bu durumda non-streamed olurdu.

    int EncryptBufferWithCallback(ALG_ID algId, const std::string& password, const std::vector<BYTE>& input, std::vector<BYTE>& encryptedOutput, 
        bool* pIsStopRequested = NULL, bool* pIsRunning = NULL, long long* pElapsedTimeMSec = NULL, int* pErrorCode = NULL,
        StartCallback start = NULL, ProgressCallback progress = NULL, CompletionCallback completion = NULL, ErrorCallback error = NULL);
    int DecryptBufferWithCallback(ALG_ID algId, const std::string& password, const std::vector<BYTE>& encryptedInput, std::vector<BYTE>& decryptedOutput,
        bool* pIsStopRequested = NULL, bool* pIsRunning = NULL, long long* pElapsedTimeMSec = NULL, int* pErrorCode = NULL,
        StartCallback start = NULL, ProgressCallback progress = NULL, CompletionCallback completion = NULL, ErrorCallback error = NULL);
    int HashBufferWithCallback(ALG_ID algId, const std::vector<BYTE>& input, std::vector<BYTE>& outputHashBytes, std::string& outputHash, 
        bool* pIsStopRequested = NULL, bool* pIsRunning = NULL, long long* pElapsedTimeMSec = NULL, int* pErrorCode = NULL,
        StartCallback start = NULL, ProgressCallback progress = NULL, CompletionCallback completion = NULL, ErrorCallback error = NULL);
    
    //--------------------------------------------------------------------------------------------------------------------------------------------------
    // String operations
    int EncryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output);
    int DecryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output);
    int HashString(ALG_ID algId, const std::string& input, std::string& outputHash);

    int EncryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output, bool& isRunning, long long& elapsedTimeMSec);
    int DecryptString(ALG_ID algId, const std::string& password, const std::string& input, std::string& output, bool& isRunning, long long& elapsedTimeMSec);
    int HashString(ALG_ID algId, const std::string& input, std::string& outputHash, bool& isRunning, long long& elapsedTimeMSec);

    //--------------------------------------------------------------------------------------------------------------------------------------------------
    // File operations
    int EncryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password);
    int DecryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password);
    int HashFile(ALG_ID algId, const std::string& inputFile, std::string& outputHash);

    int EncryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password, bool& isRunning, long long& elapsedTimeMSec);
    int DecryptFile(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password, bool& isRunning, long long& elapsedTimeMSec);
    int HashFile(ALG_ID algId, const std::string& inputFile, std::string& outputHash, bool& isRunning, long long& elapsedTimeMSec);

    //--------------------------------------------------------------------------------------------------------------------------------------------------
    // Asenkron File operations
    int EncryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password);
    int DecryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password);
    int HashFileWithCallback(ALG_ID algId, const std::string& inputFile, std::string& outputHash);

    int EncryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion);
    int DecryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion);
    int HashFileWithCallback(ALG_ID algId, const std::string& inputFile, std::string& outputHash,
        StartCallback start, ProgressCallback progress, CompletionCallback completion);

    int EncryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);
    int DecryptFileWithCallback(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);
    int HashFileWithCallback(ALG_ID algId, const std::string& inputFile, std::string& outputHash,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);

    //--------------------------------------------------------------------------------------------------------------------------------------------------
    // Asenkron File operations (Thread)
    int EncryptFileAsync(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);
    int DecryptFileAsync(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);
    int HashFileAsync(ALG_ID algId, const std::string& inputFile, std::string& outputHash,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, bool& isRunning, long long& elapsedTimeMSec);

    //--------------------------------------------------------------------------------------------------------------------------------------------------
    // Utility functions
    std::string Base64Encode(const std::vector<BYTE>& input);
    std::vector<BYTE> Base64Decode(const std::string& input);
    std::vector<BYTE> StringToBytes(const std::string& str);
    std::string BytesToString(const std::vector<BYTE>& bytes);
    std::string GetLastErrorString();


    //--------------------------------------------------------------------------------------------------------------------------------------------------
    // Timer functions
    void StartTimer(void);
    void StopTimer(void);
    long long GetElapsedTimeMsec(void);

    //--------------------------------------------------------------------------------------------------------------------------------------------------
    enum AlgorithmType {
        ENCRYPTION,
        HASH
    };

    struct AlgorithmInfo {
        ALG_ID algId;
        int keyLength;
        int blockSize;
        AlgorithmType type;
        std::string name;
    };


    int EncryptFileWithCallback_calismadi(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        bool* pIsStopRequested, bool* pIsRunning, long long* pElapsedTimeMSec, int* pErrorCode,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, ErrorCallback error);

    int DecryptFileWithCallback_calismadi(ALG_ID algId, const std::string& inputFile, const std::string& outputFile, const std::string& password,
        bool* pIsStopRequested, bool* pIsRunning, long long* pElapsedTimeMSec, int* pErrorCode,
        StartCallback start, ProgressCallback progress, CompletionCallback completion, ErrorCallback error);


    int EncryptFileStreamedWithCallback(
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
        ErrorCallback error);

    int DecryptFileStreamedWithCallback(
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
        ErrorCallback error);


    int HashFileStreamedWithCallback(
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
        ErrorCallback error);





    int EncryptStringWithCallback(ALG_ID algId, const std::string& password, const std::string& input, std::string& output,
        bool* pIsStopRequested = NULL, bool* pIsRunning = NULL, long long* pElapsedTimeMSec = NULL, int* pErrorCode = NULL,
        StartCallback start = NULL, ProgressCallback progress = NULL, CompletionCallback completion = NULL, ErrorCallback error = NULL);
    int DecryptStringWithCallback(ALG_ID algId, const std::string& password, const std::string& input, std::string& output,
        bool* pIsStopRequested = NULL, bool* pIsRunning = NULL, long long* pElapsedTimeMSec = NULL, int* pErrorCode = NULL,
        StartCallback start = NULL, ProgressCallback progress = NULL, CompletionCallback completion = NULL, ErrorCallback error = NULL);
    int HashStringWithCallback(ALG_ID algId, const std::string& input, std::string& outputHash,
        bool* pIsStopRequested = NULL, bool* pIsRunning = NULL, long long* pElapsedTimeMSec = NULL, int* pErrorCode = NULL,
        StartCallback start = NULL, ProgressCallback progress = NULL, CompletionCallback completion = NULL, ErrorCallback error = NULL);


    int EncryptStringStreamedWithCallback(
        ALG_ID algId,
        const std::string& password,
        std::istream& input,
        std::ostream& output,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);

    int DecryptStringStreamedWithCallback(
        ALG_ID algId,
        const std::string& password,
        std::istream& input,
        std::ostream& output,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);

    int HashStringStreamedWithCallback(
        ALG_ID algId,
        std::istream& input,
        std::string& outputHash,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);



    int  EncryptFileStreamedWithCallbackThread(
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
        ErrorCallback error);

    int DecryptFileStreamedWithCallbackThread(
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
        ErrorCallback error);

    int HashFileStreamedWithCallbackThread(
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
        ErrorCallback error);



    int EncryptStringStreamedWithCallbackThread(
        ALG_ID algId,
        const std::string& password,
        std::istream& input,
        std::ostream& output,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);


    int DecryptStringStreamedWithCallbackThread(
        ALG_ID algId,
        const std::string& password,
        std::istream& input,
        std::ostream& output,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);

    int HashStringStreamedWithCallbackThread(
        ALG_ID algId,
        std::istream& input,
        std::string& outputHash,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);


    int EncryptBufferWithCallbackThread(
        ALG_ID algId,
        const std::string& password,
        const std::vector<BYTE>& input,
        std::vector<BYTE>& encryptedOutput,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);

    int DecryptBufferWithCallbackThread(
        ALG_ID algId,
        const std::string& password,
        const std::vector<BYTE>& encryptedInput,
        std::vector<BYTE>& decryptedOutput,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);

    int HashBufferWithCallbackThread(
        ALG_ID algId,
        const std::vector<BYTE>& input,
        std::vector<BYTE>& outputHashBytes,
        std::string& outputHash,
        bool* pIsStopRequested,
        bool* pIsRunning,
        long long* pElapsedTimeMSec,
        int* pErrorCode,
        StartCallback start,
        ProgressCallback progress,
        CompletionCallback completion,
        ErrorCallback error);

protected:

private:
    std::atomic<bool> m_isRunning;
    std::map<ALG_ID, AlgorithmInfo> m_supportedAlgorithms;

    HCRYPTPROV GetCryptProvider() const;
    HCRYPTKEY GenerateKey(ALG_ID algId, HCRYPTPROV hProv, const std::string& password);
    bool ValidateAlgorithm(ALG_ID algId, AlgorithmType expectedType) const;

    long long getElapsedTimeMSec(std::chrono::time_point<std::chrono::steady_clock>& m_startTime, std::chrono::time_point<std::chrono::steady_clock>& m_currentTime) const;
    long long getElapsedTimeMSecUpToNow(std::chrono::time_point<std::chrono::steady_clock>& m_startTime) const;

    // Status check
    bool IsRunning() const;

    bool IsStartTimerCalled;
    bool IsStopTimerCalled;
    std::chrono::time_point<std::chrono::steady_clock> m_startTime;
    std::chrono::time_point<std::chrono::steady_clock> m_stopTime;
};

#endif // CryptoHandlerH
