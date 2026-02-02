// mylib_keygen.cpp
// cl /std:c++17 /O2 mylib_keygen.cpp /link Bcrypt.lib
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>
#include <cstdio>

#pragma comment(lib, "Bcrypt.lib")

static void Fail(const char* m) { throw std::runtime_error(m); }

static void WriteAll(const std::wstring& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) Fail("open output failed");
    f.write((const char*)data.data(), (std::streamsize)data.size());
    if (!f) Fail("write failed");
}

static std::vector<uint8_t> ExportKey(BCRYPT_KEY_HANDLE hKey, LPCWSTR blobType)
{
    DWORD cb = 0;
    if (BCryptExportKey(hKey, nullptr, blobType, nullptr, 0, &cb, 0) != 0)
        Fail("BCryptExportKey(size) failed");
    std::vector<uint8_t> b(cb);
    if (BCryptExportKey(hKey, nullptr, blobType, b.data(), cb, &cb, 0) != 0)
        Fail("BCryptExportKey(data) failed");
    b.resize(cb);
    return b;
}

int wmain()
{
    try {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0)
            Fail("BCryptOpenAlgorithmProvider(ECDSA_P256) failed");

        BCRYPT_KEY_HANDLE hKey = nullptr;
        if (BCryptGenerateKeyPair(hAlg, &hKey, 256, 0) != 0)
            Fail("BCryptGenerateKeyPair failed");
        if (BCryptFinalizeKeyPair(hKey, 0) != 0)
            Fail("BCryptFinalizeKeyPair failed");

        auto priv = ExportKey(hKey, BCRYPT_ECCPRIVATE_BLOB);
        auto pub = ExportKey(hKey, BCRYPT_ECCPUBLIC_BLOB);

        WriteAll(L"mylib_priv.key", priv);
        WriteAll(L"mylib_pub.key", pub);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        std::wprintf(L"[OK] Wrote mylib_priv.key (%zu bytes)\n", priv.size());
        std::wprintf(L"[OK] Wrote mylib_pub.key  (%zu bytes)\n", pub.size());
        return 0;
    }
    catch (const std::exception& e) {
        std::printf("[ERR] %s\n", e.what());
        return 2;
    }
}

