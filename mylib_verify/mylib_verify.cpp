// mylib_verify.cpp - verifies ECDSA P-256 signature on .mylib (format v2 from mylib_pack_fixed.cpp)
// Build:
//   cl /std:c++17 /O2 mylib_verify.cpp /link Bcrypt.lib
//
// Usage:
//   mylib_verify.exe path\to\plugin.mylib [path\to\mylib_pub.key]
//
// Notes:
// - Expects signature trailer: sigDER + uint32_t sigLen (sigLen is last 4 bytes)
// - Verifies over all bytes BEFORE the trailer (signedSize bytes).

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <fstream>
#include <stdexcept>

#pragma comment(lib, "Bcrypt.lib")

static void Fail(const char* m) { throw std::runtime_error(m); }

static std::wstring ToW(const std::string& s)
{
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), (wchar_t*)w.data(), n);
    return w;
}

static std::vector<uint8_t> ReadAll(const std::wstring& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f) Fail("Failed to open file");
    f.seekg(0, std::ios::end);
    size_t sz = (size_t)f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(sz);
    if (sz && !f.read((char*)buf.data(), (std::streamsize)sz)) Fail("Failed to read file");
    return buf;
}

static std::vector<uint8_t> Sha256Bytes(const uint8_t* data, size_t size)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    DWORD cbObj = 0, cbHash = 0, cb = 0;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != 0)
        Fail("BCryptOpenAlgorithmProvider(SHA256) failed");

    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj, sizeof(cbObj), &cb, 0) != 0 ||
        BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PUCHAR)&cbHash, sizeof(cbHash), &cb, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Fail("BCryptGetProperty(SHA256) failed");
    }

    std::vector<uint8_t> obj(cbObj), hash(cbHash);

    if (BCryptCreateHash(hAlg, &hHash, obj.data(), cbObj, nullptr, 0, 0) != 0 ||
        BCryptHashData(hHash, (PUCHAR)data, (ULONG)size, 0) != 0 ||
        BCryptFinishHash(hHash, hash.data(), (ULONG)hash.size(), 0) != 0)
    {
        if (hHash) BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Fail("SHA256 failed");
    }

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return hash;
}

static BCRYPT_KEY_HANDLE ImportEccPublicKeyP256(const std::vector<uint8_t>& pubBlob)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0)
        Fail("BCryptOpenAlgorithmProvider(ECDSA_P256) failed");

    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
        &hKey, (PUCHAR)pubBlob.data(), (ULONG)pubBlob.size(), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0) Fail("BCryptImportKeyPair(PUB) failed");
    return hKey;
}

static bool EcdsaP256VerifySha256(BCRYPT_KEY_HANDLE hPubKey,
    const uint8_t* data, size_t size,
    const uint8_t* sig, size_t sigSize)
{
    auto hash = Sha256Bytes(data, size);
    NTSTATUS st = BCryptVerifySignature(hPubKey, nullptr,
        (PUCHAR)hash.data(), (ULONG)hash.size(),
        (PUCHAR)sig, (ULONG)sigSize, 0);
    return st == 0;
}

#pragma pack(push, 1)
struct MyLibHeaderV2
{
    uint8_t  magic[4];     // 'M''Y''L''B'
    uint16_t version;      // 2
    uint16_t flags;        // 0
    uint32_t metaSize;     // bytes
    uint32_t payloadSize;  // ciphertext bytes
    uint8_t  nonce[12];    // GCM nonce
    uint32_t sigAlg;       // 1 = ECDSA_P256_SHA256
    uint32_t reserved0;
    uint8_t  reserved[8];  // future use
};
#pragma pack(pop)

static uint32_t ReadU32LE(const uint8_t* p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int main(int argc, char** argv)
{
    try
    {
        if (argc < 2)
        {
            std::fprintf(stderr,
                "Usage:\n"
                "  mylib_verify.exe file.mylib [mylib_pub.key]\n");
            return 1;
        }

        std::wstring mylibPath = ToW(argv[1]);
        std::wstring pubPath = (argc >= 3) ? ToW(argv[2]) : L"mylib_pub.key";

        auto file = ReadAll(mylibPath);
        if (file.size() < sizeof(MyLibHeaderV2) + 4 + 16) Fail("File too small");

        // Parse signature trailer (layout): [... signed_data ...][sigDER][u32 sigLen]
        uint32_t sigLen = ReadU32LE(&file[file.size() - 4]);
        if (sigLen == 0 || sigLen > 4096) Fail("Invalid sigLen");
        size_t signedSize = file.size() - 4 - sigLen;
        if (signedSize < sizeof(MyLibHeaderV2)) Fail("Invalid signedSize");

        const uint8_t* sig = &file[signedSize];
        // Basic header sanity
        if (signedSize < sizeof(MyLibHeaderV2)) Fail("Missing header");
        const MyLibHeaderV2* hdr = (const MyLibHeaderV2*)file.data();
        if (!(hdr->magic[0] == 'M' && hdr->magic[1] == 'Y' && hdr->magic[2] == 'L' && hdr->magic[3] == 'B'))
            Fail("Bad magic");
        if (hdr->version != 2) Fail("Unsupported version (expected 2)");
        if (hdr->sigAlg != 1) Fail("Unsupported sigAlg");

        // Verify signature
        auto pubBlob = ReadAll(pubPath);
        BCRYPT_KEY_HANDLE hPub = ImportEccPublicKeyP256(pubBlob);

        bool ok = EcdsaP256VerifySha256(hPub, file.data(), signedSize, sig, sigLen);
        BCryptDestroyKey(hPub);

        if (!ok)
        {
            std::printf("[FAIL] Signature INVALID\n");
            return 3;
        }

        std::printf("[OK] Signature VALID\n");
        std::printf("     Signed bytes: %zu\n", signedSize);
        std::printf("     Signature bytes (DER): %u\n", sigLen);
        return 0;
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "[ERR] %s\n", e.what());
        return 2;
    }
}
