// mylib_pack.cpp (portable, no DPAPI) - FINAL
// Packs a WASM module into a private .mylib container.
//
// Features:
//  - AES-256-GCM encryption (CNG/BCrypt)
//  - AES key stored as raw 32-byte file: mylib_aeskey.bin (portable; keep secret)
//  - ECDSA P-256 signature (SHA-256) over: header + metadata + ciphertext + tag
//    Signature is appended at end: sigDER + uint32 sigLen (sigLen in last 4 bytes)
//  - Signing keys are generated on first run if missing:
//      mylib_priv.key (ECCPRIVATE_BLOB)  <-- keep secret
//      mylib_pub.key  (ECCPUBLIC_BLOB)  <-- embed/ship for verification
//
// Build (MSVC Dev Prompt):
//   cl /std:c++17 /O2 mylib_pack.cpp /link Bcrypt.lib
//
// Usage:
//   mylib_pack.exe plugin1.wasm plugin1.mylib --name "demo" --ver "1.0.0"
//
// Notes:
//  - Metadata JSON bytes are used as AES-GCM AAD (tampering breaks decrypt).
//  - Signature prevents file replacement/tampering (verify before decrypt).

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
    if (!f) Fail("Failed to open file for reading");
    f.seekg(0, std::ios::end);
    size_t sz = (size_t)f.tellg();
    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(sz);
    if (sz && !f.read((char*)buf.data(), (std::streamsize)sz)) Fail("Failed to read file");
    return buf;
}

static void WriteAll(const std::wstring& path, const std::vector<uint8_t>& data)
{
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) Fail("Failed to open file for writing");
    if (!data.empty()) f.write((const char*)data.data(), (std::streamsize)data.size());
    if (!f) Fail("Failed to write file");
}

static bool FileExists(const std::wstring& path)
{
    DWORD a = GetFileAttributesW(path.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static std::vector<uint8_t> RngBytes(size_t n)
{
    std::vector<uint8_t> b(n);
    if (BCryptGenRandom(nullptr, b.data(), (ULONG)b.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
        Fail("BCryptGenRandom failed");
    return b;
}

static void Append(std::vector<uint8_t>& out, const void* p, size_t n)
{
    const uint8_t* b = (const uint8_t*)p;
    out.insert(out.end(), b, b + n);
}

// ----------------- Portable AES key store -----------------
static std::vector<uint8_t> LoadOrCreateAesKey32(const std::wstring& keyPath)
{
    if (FileExists(keyPath))
    {
        auto key = ReadAll(keyPath);
        if (key.size() != 32) Fail("AES key file invalid (expected exactly 32 bytes)");
        return key;
    }
    auto key = RngBytes(32);
    WriteAll(keyPath, key);
    return key;
}

// ----------------- SHA-256 -----------------
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

// ----------------- AES-256-GCM -----------------
struct GcmEncrypted
{
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag; // 16 bytes
};

static GcmEncrypted Aes256GcmEncrypt(
    const std::vector<uint8_t>& key32,
    const std::vector<uint8_t>& nonce12,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad)
{
    if (key32.size() != 32) Fail("AES key must be 32 bytes");
    if (nonce12.size() != 12) Fail("GCM nonce must be 12 bytes");

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_KEY_HANDLE hKey = nullptr;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
        Fail("BCryptOpenAlgorithmProvider(AES) failed");

    if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
        (ULONG)(wcslen(BCRYPT_CHAIN_MODE_GCM) * sizeof(wchar_t)), 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Fail("BCryptSetProperty(GCM) failed");
    }

    DWORD cbKeyObj = 0, cbRes = 0;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObj, sizeof(cbKeyObj), &cbRes, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Fail("BCryptGetProperty(OBJECT_LENGTH) failed");
    }

    std::vector<uint8_t> keyObj(cbKeyObj);

    if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), (ULONG)keyObj.size(),
        (PUCHAR)key32.data(), (ULONG)key32.size(), 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Fail("BCryptGenerateSymmetricKey failed");
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    BCRYPT_INIT_AUTH_MODE_INFO(info);

    info.pbNonce = (PUCHAR)nonce12.data();
    info.cbNonce = (ULONG)nonce12.size();

    info.pbAuthData = (PUCHAR)aad.data();
    info.cbAuthData = (ULONG)aad.size();

    std::vector<uint8_t> tag(16);
    info.pbTag = tag.data();
    info.cbTag = (ULONG)tag.size();

    std::vector<uint8_t> ct(plaintext.size());
    ULONG cbOut = 0;

    NTSTATUS st = BCryptEncrypt(
        hKey,
        (PUCHAR)plaintext.data(), (ULONG)plaintext.size(),
        &info,
        nullptr, 0,
        ct.data(), (ULONG)ct.size(),
        &cbOut,
        0
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (st != 0 || cbOut != ct.size())
        Fail("BCryptEncrypt(AES-GCM) failed");

    return GcmEncrypted{ std::move(ct), std::move(tag) };
}

// ----------------- ECDSA P-256 keygen/import/sign -----------------
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

static void EnsureSigningKeysExist(const std::wstring& privPath, const std::wstring& pubPath)
{
    if (FileExists(privPath) && FileExists(pubPath))
        return;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0)
        Fail("BCryptOpenAlgorithmProvider(ECDSA_P256) failed");

    BCRYPT_KEY_HANDLE hKey = nullptr;
    if (BCryptGenerateKeyPair(hAlg, &hKey, 256, 0) != 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Fail("BCryptGenerateKeyPair failed");
    }

    if (BCryptFinalizeKeyPair(hKey, 0) != 0)
    {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        Fail("BCryptFinalizeKeyPair failed");
    }

    auto priv = ExportKey(hKey, BCRYPT_ECCPRIVATE_BLOB);
    auto pub = ExportKey(hKey, BCRYPT_ECCPUBLIC_BLOB);

    WriteAll(privPath, priv);
    WriteAll(pubPath, pub);

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
}

static BCRYPT_KEY_HANDLE ImportEccPrivateKeyP256(const std::vector<uint8_t>& privBlob)
{
    BCRYPT_ALG_HANDLE hAlg = nullptr;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0) != 0)
        Fail("OpenAlgorithmProvider(ECDSA_P256) failed");

    BCRYPT_KEY_HANDLE hKey = nullptr;
    NTSTATUS st = BCryptImportKeyPair(hAlg, nullptr, BCRYPT_ECCPRIVATE_BLOB,
        &hKey, (PUCHAR)privBlob.data(), (ULONG)privBlob.size(), 0);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0) Fail("BCryptImportKeyPair(PRIV) failed");
    return hKey;
}

static std::vector<uint8_t> EcdsaP256SignSha256(BCRYPT_KEY_HANDLE hPrivKey,
    const uint8_t* data, size_t size)
{
    auto hash = Sha256Bytes(data, size);

    DWORD sigLen = 0;
    // BCryptSignHash has 8 parameters (note pcbResult + flags).
    if (BCryptSignHash(hPrivKey, nullptr,
        (PUCHAR)hash.data(), (ULONG)hash.size(),
        nullptr, 0, &sigLen, 0) != 0)
        Fail("BCryptSignHash(size) failed");

    std::vector<uint8_t> sig(sigLen);
    if (BCryptSignHash(hPrivKey, nullptr,
        (PUCHAR)hash.data(), (ULONG)hash.size(),
        sig.data(), (ULONG)sig.size(), &sigLen, 0) != 0)
        Fail("BCryptSignHash(data) failed");

    sig.resize(sigLen); // DER signature
    return sig;
}

// ----------------- Metadata -----------------
static std::vector<uint8_t> MakeMetadataJson(const std::string& name, const std::string& ver, size_t wasmSize)
{
    // Minimal JSON in UTF-8
    std::string j = "{";
    j += "\"name\":\"" + name + "\",";
    j += "\"version\":\"" + ver + "\",";
    j += "\"wasm_size\":" + std::to_string((uint64_t)wasmSize);
    j += "}";
    return std::vector<uint8_t>(j.begin(), j.end());
}

// ----------------- Container header -----------------
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

static std::string GetArgValue(int& i, int argc, char** argv)
{
    if (i + 1 >= argc) Fail("Missing value for argument");
    return argv[++i];
}

int main(int argc, char** argv)
{
    try
    {
        if (argc < 3)
        {
            std::fprintf(stderr,
                "Usage:\n"
                "  mylib_pack.exe input.wasm output.mylib --name \"demo\" --ver \"1.0.0\"\n");
            return 1;
        }

        std::wstring inPath = ToW(argv[1]);
        std::wstring outPath = ToW(argv[2]);

        std::string name = "plugin";
        std::string ver = "1.0.0";

        for (int i = 3; i < argc; ++i)
        {
            std::string a = argv[i];
            if (a == "--name") name = GetArgValue(i, argc, argv);
            else if (a == "--ver") ver = GetArgValue(i, argc, argv);
            else Fail("Unknown argument");
        }

        // Files created/used by builder (keep priv.key secret!)
        const std::wstring aesKeyPath = L"mylib_aeskey.bin"; // raw 32-byte AES key
        const std::wstring privKeyPath = L"mylib_priv.key";   // ECCPRIVATE_BLOB
        const std::wstring pubKeyPath = L"mylib_pub.key";    // ECCPUBLIC_BLOB

        EnsureSigningKeysExist(privKeyPath, pubKeyPath);

        auto aesKey32 = LoadOrCreateAesKey32(aesKeyPath);

        auto privBlob = ReadAll(privKeyPath);
        BCRYPT_KEY_HANDLE hPriv = ImportEccPrivateKeyP256(privBlob);

        auto wasm = ReadAll(inPath);
        if (wasm.size() < 8) Fail("Input is too small to be a valid wasm");

        auto meta = MakeMetadataJson(name, ver, wasm.size());

        auto nonce = RngBytes(12);
        auto enc = Aes256GcmEncrypt(aesKey32, nonce, wasm, meta);

        MyLibHeaderV2 hdr{};
        hdr.magic[0] = 'M'; hdr.magic[1] = 'Y'; hdr.magic[2] = 'L'; hdr.magic[3] = 'B';
        hdr.version = 2;
        hdr.flags = 0;
        hdr.metaSize = (uint32_t)meta.size();
        hdr.payloadSize = (uint32_t)enc.ciphertext.size();
        std::memcpy(hdr.nonce, nonce.data(), 12);
        hdr.sigAlg = 1;

        std::vector<uint8_t> out;
        out.reserve(sizeof(hdr) + meta.size() + enc.ciphertext.size() + enc.tag.size() + 4 + 128);

        Append(out, &hdr, sizeof(hdr));
        Append(out, meta.data(), meta.size());
        Append(out, enc.ciphertext.data(), enc.ciphertext.size());
        Append(out, enc.tag.data(), enc.tag.size()); // 16 bytes

        auto sig = EcdsaP256SignSha256(hPriv, out.data(), out.size());
        BCryptDestroyKey(hPriv);

        uint32_t sigLen = (uint32_t)sig.size();
        Append(out, sig.data(), sig.size());
        Append(out, &sigLen, sizeof(sigLen));
        WriteAll(outPath, out);

        std::printf("[OK] Packed+Signed: %ls\n", outPath.c_str());
        std::printf("     meta=%u bytes, ct=%u bytes, tag=16, sig=%u bytes\n",
            hdr.metaSize, hdr.payloadSize, sigLen);
        std::printf("     AES key:      %ls (raw 32 bytes; portable)\n", aesKeyPath.c_str());
        std::printf("     Sign keys:    %ls (private), %ls (public)\n", privKeyPath.c_str(), pubKeyPath.c_str());
        std::printf("     IMPORTANT: keep mylib_priv.key secret; ship/embed only mylib_pub.key.\n");
        return 0;
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "[ERR] %s\n", e.what());
        return 2;
    }
}
