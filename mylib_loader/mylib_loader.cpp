// mylib_loader.cpp - verify + decrypt + run WASM from .mylib (format v2 from mylib_pack_fixed.cpp)
//
// What it does:
//  1) Reads .mylib container
//  2) Parses header, extracts metadata (AAD), nonce, ciphertext, tag
//  3) Verifies ECDSA P-256 signature using mylib_pub.key
//  4) Decrypts payload using AES-256-GCM with a 32-byte AES key file (mylib_aeskey.bin)
//  5) Hands decrypted WASM bytes to a WASM runtime (choose one below)
//
// IMPORTANT CLARIFICATION:
//  - Decryption is NOT done "by public key". The public key is only for SIGNATURE verification.
//  - Decryption uses the symmetric AES-256 key (mylib_aeskey.bin). Keep this key secret.
//
// Build (MSVC):
//   cl /std:c++17 /O2 mylib_loader.cpp /link Bcrypt.lib
//
// Runtime integration:
//  - This file contains a small "adapter" function RunWasm(...) that you must implement by
//    choosing a runtime. The simplest embedded runtime for Windows projects is usually WASM3.
//  - See the "WASM RUNTIME OPTIONS" section at the bottom of this file.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

// wasm3 headers (add wasm3 repo /source to include path)
#include "wasm3.h"
#include "m3_env.h"

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

static bool FileExists(const std::wstring& path)
{
    DWORD a = GetFileAttributesW(path.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
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

static void FailNt(const char* what, NTSTATUS st)
{
    char buf[256];
    std::snprintf(buf, sizeof(buf), "%s (NTSTATUS=0x%08X)", what, (unsigned)st);
    throw std::runtime_error(buf);
}

static BCRYPT_KEY_HANDLE ImportEccPublicKeyP256(const std::vector<uint8_t>& pubBlob)
{
    // Expect raw BCRYPT_ECCPUBLIC_BLOB exported by BCryptExportKey:
    // BCRYPT_ECCKEY_BLOB (8 bytes) + X(32) + Y(32) = 72 bytes for P-256
    if (pubBlob.size() != 72)
        Fail("mylib_pub.key has unexpected size. Expected 72 bytes (BCRYPT_ECCPUBLIC_BLOB for P-256).");

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    NTSTATUS st = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, nullptr, 0);
    if (st != 0) FailNt("BCryptOpenAlgorithmProvider(ECDSA_P256) failed", st);

    BCRYPT_KEY_HANDLE hKey = nullptr;
    st = BCryptImportKeyPair(
        hAlg, nullptr, BCRYPT_ECCPUBLIC_BLOB,
        &hKey, (PUCHAR)pubBlob.data(), (ULONG)pubBlob.size(), 0);

    BCryptCloseAlgorithmProvider(hAlg, 0);
    if (st != 0 || !hKey) FailNt("BCryptImportKeyPair(ECCPUBLIC_BLOB) failed", st);

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
    uint8_t  reserved[8];
};
#pragma pack(pop)

static std::vector<uint8_t> LoadAesKey32(const std::wstring& path)
{
    if (!FileExists(path)) Fail("AES key file not found (mylib_aeskey.bin)");
    auto key = ReadAll(path);
    if (key.size() != 32) Fail("AES key file invalid (expected exactly 32 bytes)");
    return key;
}

// AES-256-GCM decrypt
static std::vector<uint8_t> Aes256GcmDecrypt(
    const std::vector<uint8_t>& key32,
    const uint8_t nonce12[12],
    const uint8_t* ciphertext, size_t ciphertextSize,
    const uint8_t tag16[16],
    const uint8_t* aad, size_t aadSize)
{
    if (key32.size() != 32) Fail("AES key must be 32 bytes");

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

    info.pbNonce = (PUCHAR)nonce12;
    info.cbNonce = 12;

    info.pbAuthData = (PUCHAR)aad;
    info.cbAuthData = (ULONG)aadSize;

    info.pbTag = (PUCHAR)tag16;
    info.cbTag = 16;

    std::vector<uint8_t> pt(ciphertextSize);
    ULONG cbOut = 0;

    NTSTATUS st = BCryptDecrypt(
        hKey,
        (PUCHAR)ciphertext, (ULONG)ciphertextSize,
        &info,
        nullptr, 0,
        pt.data(), (ULONG)pt.size(),
        &cbOut,
        0
    );

    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (st != 0) Fail("BCryptDecrypt(AES-GCM) failed (bad key/tag/AAD?)");
    if (cbOut != pt.size()) Fail("BCryptDecrypt output size mismatch");

    return pt;
}

// ----------------- WASM runtime hook -----------------
// Implement this using your chosen runtime (WASM3 / WAMR / Wasmtime / Wasmer).
// For MVP you can just validate the header (0x00 0x61 0x73 0x6D) and return true.

static m3ApiRawFunction(Host_show_message)
{
    m3ApiGetArgMem(const char*, msg);
    m3ApiGetArg(int32_t, len);

    if (!msg || len < 0) m3ApiSuccess();

    std::string s(msg, msg + len);
    MessageBoxA(nullptr, s.c_str(), "WASM Plugin", MB_OK | MB_ICONINFORMATION);

    m3ApiSuccess();
}

static bool RunWasm(const std::vector<uint8_t>& wasmBytes)
{
    if (wasmBytes.size() < 8)
        return false;

    // WASM magic: 00 61 73 6D
    if (!(wasmBytes[0] == 0x00 && wasmBytes[1] == 0x61 && wasmBytes[2] == 0x73 && wasmBytes[3] == 0x6D))
    {
        wprintf(L"[ERR] Not a wasm module (bad magic)\n");
        return false;
    }

    IM3Environment env = m3_NewEnvironment();
    if (!env)
    {
        wprintf(L"[ERR] m3_NewEnvironment failed\n");
        return false;
    }

    // stack size: 64KB (tweak if needed)
    IM3Runtime runtime = m3_NewRuntime(env, 64 * 1024, nullptr);
    if (!runtime)
    {
        wprintf(L"[ERR] m3_NewRuntime failed\n");
        m3_FreeEnvironment(env);
        return false;
    }

    IM3Module module = nullptr;
    M3Result res = m3_ParseModule(env, &module, wasmBytes.data(), (uint32_t)wasmBytes.size());
    if (res)
    {
        wprintf(L"[ERR] m3_ParseModule: %hs\n", res);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return false;
    }

    res = m3_LoadModule(runtime, module);
    if (res)
    {
        wprintf(L"[ERR] m3_LoadModule: %hs\n", res);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return false;
    }

    // Link host function:
    //   (import "host" "show_message" (func (param i32 i32)))
    // wasm3 signature format: "v(*i)" = void (char*, int32)
    res = m3_LinkRawFunction(module, "host", "show_message", "v(*i)", &Host_show_message);
    if (res)
    {
        wprintf(L"[ERR] m3_LinkRawFunction(host.show_message): %hs\n", res);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return false;
    }

    IM3Function f = nullptr;
    res = m3_FindFunction(&f, runtime, "plugin_main");
    if (res)
    {
        wprintf(L"[ERR] m3_FindFunction(plugin_main): %hs\n", res);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return false;
    }

    res = m3_CallV(f);
    if (res)
    {
        wprintf(L"[ERR] m3_CallV(plugin_main): %hs\n", res);
        m3_FreeRuntime(runtime);
        m3_FreeEnvironment(env);
        return false;
    }

    // If plugin_main returns i32, try to read it (if it was void, wasm3 may return an error here)
    int32_t ret = 0;
    res = m3_GetResultsV(f, &ret);
    if (!res)
        wprintf(L"[OK] plugin_main returned: %d\n", (int)ret);

    m3_FreeRuntime(runtime);
    m3_FreeEnvironment(env);
    return true;
}

struct ParsedMyLib
{
    MyLibHeaderV2 hdr{};
    std::vector<uint8_t> meta;       // AAD
    const uint8_t* ciphertext = nullptr;
    size_t ciphertextSize = 0;
    const uint8_t* tag = nullptr;    // 16 bytes
    const uint8_t* sig = nullptr;    // 64 bytes (P1363 r||s)
    uint32_t sigLen = 0;
    size_t signedSize = 0;
};

static ParsedMyLib ParseMyLibV2(const std::vector<uint8_t>& file)
{
    ParsedMyLib p{};

    if (file.size() < sizeof(MyLibHeaderV2) + 16 + 4) Fail("File too small");
    std::memcpy(&p.hdr, file.data(), sizeof(MyLibHeaderV2));

    if (!(p.hdr.magic[0] == 'M' && p.hdr.magic[1] == 'Y' && p.hdr.magic[2] == 'L' && p.hdr.magic[3] == 'B'))
        Fail("Bad magic");
    if (p.hdr.version != 2) Fail("Unsupported version (expected 2)");
    if (p.hdr.sigAlg != 1) Fail("Unsupported sigAlg (expected 1)");

    const size_t offMeta = sizeof(MyLibHeaderV2);
    const size_t offCt = offMeta + p.hdr.metaSize;
    const size_t offTag = offCt + p.hdr.payloadSize;
    const size_t offSigLen = offTag + 16;

    if (file.size() < offSigLen + 4) Fail("Truncated file (missing sigLen)");
    if (offCt < offMeta) Fail("Overflow");
    if (offTag < offCt) Fail("Overflow");

    // signed data is everything up to (tag end)
    p.signedSize = offTag + 16;

    // metadata
    p.meta.assign(file.begin() + offMeta, file.begin() + offCt);

    // ciphertext pointer
    p.ciphertext = file.data() + offCt;
    p.ciphertextSize = p.hdr.payloadSize;

    // tag pointer
    p.tag = file.data() + offTag;

    // trailer (layout): [... signed_data ...][sigDER][u32 sigLen]  (sigLen is last 4 bytes)
    if (file.size() < p.signedSize + 4) Fail("Truncated file (missing signature trailer)");

    uint32_t sigLen = *(const uint32_t*)(&file[file.size() - 4]);
    p.sigLen = sigLen;

    if (sigLen == 0 || sigLen > 4096) Fail("Invalid sigLen");

    size_t offSig = file.size() - 4 - (size_t)sigLen;

    // Signature must start immediately after tag (strict layout)
    if (offSig != p.signedSize) Fail("Unexpected layout/extra bytes before signature");

    p.sig = file.data() + offSig;

    return p;
}

int main(int argc, char** argv)
{
    try
    {
        if (argc < 2)
        {
            std::fprintf(stderr,
                "Usage:\n"
                "  mylib_loader.exe file.mylib [mylib_pub.key] [mylib_aeskey.bin]\n");
            return 1;
        }

        std::wstring mylibPath = ToW(argv[1]);
        std::wstring pubPath = (argc >= 3) ? ToW(argv[2]) : L"mylib_pub.key";
        std::wstring aesPath = (argc >= 4) ? ToW(argv[3]) : L"mylib_aeskey.bin";

        auto file = ReadAll(mylibPath);
        auto p = ParseMyLibV2(file);

        // 1) Verify signature first
        auto pubBlob = ReadAll(pubPath);
        BCRYPT_KEY_HANDLE hPub = ImportEccPublicKeyP256(pubBlob);

        bool ok = EcdsaP256VerifySha256(hPub, file.data(), p.signedSize, p.sig, p.sigLen);
        BCryptDestroyKey(hPub);

        if (!ok)
        {
            std::printf("[FAIL] Signature INVALID\n");
            return 3;
        }
        std::printf("[OK] Signature VALID\n");

        // 2) Decrypt payload using AES key
        auto aesKey32 = LoadAesKey32(aesPath);

        uint8_t nonce[12];
        std::memcpy(nonce, p.hdr.nonce, 12);

        uint8_t tag[16];
        std::memcpy(tag, p.tag, 16);

        auto wasm = Aes256GcmDecrypt(aesKey32, nonce, p.ciphertext, p.ciphertextSize, tag,
            p.meta.data(), p.meta.size());

        // 3) Run wasm (you plug a runtime here)
        if (!RunWasm(wasm))
        {
            std::printf("[FAIL] RunWasm failed\n");
            return 4;
        }

        return 0;
    }
    catch (const std::exception& e)
    {
        std::fprintf(stderr, "[ERR] %s\n", e.what());
        return 2;
    }
}

/*
==================== WASM RUNTIME OPTIONS ====================

You asked to "реализуй WASM runtime". A full WASM engine is a large project.
The practical approach is to EMBED an existing small runtime into your EXE.

Option A (very small, easy): WASM3
- Add WASM3 sources to your project (usually: wasm3.c + m3_api_* + m3_env.c etc).
- Then in RunWasm(...) do:
    IM3Environment env = m3_NewEnvironment();
    IM3Runtime rt = m3_NewRuntime(env, stackSize, NULL);
    IM3Module mod; m3_ParseModule(env, &mod, wasmBytes.data(), (u32)wasmBytes.size());
    m3_LoadModule(rt, mod);
    IM3Function f; m3_FindFunction(&f, rt, "plugin_main");
    const char* res = m3_CallV(f, ...);
  (Exact file set depends on WASM3 version.)

Option B (embedded official): WAMR (WebAssembly Micro Runtime)
- Heavier than WASM3 but still embeddable, supports more features.

Option C (powerful): Wasmtime / Wasmer (C API)
- Great but bigger and adds binaries or build steps.

If you tell me which runtime you want (WASM3 or WAMR is best for "single exe"),
I'll give you the exact RunWasm() implementation and the minimal file list + VS settings.
*/