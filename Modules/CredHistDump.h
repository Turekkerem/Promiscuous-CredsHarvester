#ifndef CREDHIST_DUMP_H
#define CREDHIST_DUMP_H

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <shlobj.h>
#include <algorithm>
#include <cstring>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

namespace CredHistDump {

    struct CredHistEntry {
        DWORD dwVersion;
        BYTE  guidLink[16];
        DWORD dwNextLinkSize;
        DWORD dwCredLinkType;
        DWORD algHash;         
        DWORD dwPbkdf2IterationCount;
        DWORD dwSidSize;
        DWORD algCrypt;        
        DWORD dwShaHashSize;
        DWORD dwNtHashSize;
        BYTE  salt[16];
        std::vector<BYTE> sid;
        std::vector<BYTE> encrypted; 
        std::vector<BYTE> decryptedSha;
        std::vector<BYTE> decryptedNt;
    };

    inline std::vector<BYTE> ReadFileBytes(const std::wstring& path) {
        std::ifstream f(std::filesystem::path(path), std::ios::binary);
        if (!f) return {};
        return std::vector<BYTE>((std::istreambuf_iterator<char>(f)), {});
    }

    inline std::wstring GetCredHistPath() {
        wchar_t* appdata = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)))
            return L"";
        std::wstring p = std::wstring(appdata) + L"\\Microsoft\\Protect\\CREDHIST";
        CoTaskMemFree(appdata);
        return p;
    }

    inline std::string ToHex(const BYTE* data, size_t len) {
        std::ostringstream oss;
        for (size_t i = 0; i < len; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        return oss.str();
    }

    inline bool ParseEntryAt(const std::vector<BYTE>& data, size_t offset, CredHistEntry& entry) {
        if (offset + 68 > data.size()) return false;

        size_t curr = offset;
        std::memcpy(&entry.dwVersion, data.data() + curr, 4); curr += 4;
        std::memcpy(entry.guidLink, data.data() + curr, 16); curr += 16;
        std::memcpy(&entry.dwNextLinkSize, data.data() + curr, 4); curr += 4;
        std::memcpy(&entry.dwCredLinkType, data.data() + curr, 4); curr += 4;
        std::memcpy(&entry.algHash, data.data() + curr, 4); curr += 4;
        std::memcpy(&entry.dwPbkdf2IterationCount, data.data() + curr, 4); curr += 4;
        std::memcpy(&entry.dwSidSize, data.data() + curr, 4); curr += 4;
        std::memcpy(&entry.algCrypt, data.data() + curr, 4); curr += 4;
        std::memcpy(&entry.dwShaHashSize, data.data() + curr, 4); curr += 4;
        std::memcpy(&entry.dwNtHashSize, data.data() + curr, 4); curr += 4;
        std::memcpy(entry.salt, data.data() + curr, 16); curr += 16;

        if (entry.dwVersion != 1 && entry.dwVersion != 2 && entry.dwVersion != 0) return false;
        if (entry.dwSidSize > 256) return false;
        if (entry.dwShaHashSize > 64 || entry.dwNtHashSize > 64) return false;
        if (entry.dwPbkdf2IterationCount > 50000000) return false;

        if (entry.dwSidSize > 0) {
            if (curr + entry.dwSidSize > data.size()) return false;
            entry.sid.assign(data.begin() + curr, data.begin() + curr + entry.dwSidSize);
            curr += entry.dwSidSize;
        }

        DWORD plainLen = entry.dwShaHashSize + entry.dwNtHashSize;
        if (plainLen == 0 || plainLen > 256) return false;
        DWORD encLen = plainLen + (16 - (plainLen % 16)) % 16;
        if (curr + encLen > data.size()) return false;
        entry.encrypted.assign(data.begin() + curr, data.begin() + curr + encLen);
        curr += encLen;

        return true;
    }

    inline std::vector<CredHistEntry> ParseCredHist(const std::vector<BYTE>& data) {
        std::vector<CredHistEntry> entries;
        if (data.size() < 20) return entries;

        size_t validOffset = std::string::npos;
        std::vector<size_t> candidateOffsets = {20, 0, 4, 16, 24, 32};

        for (size_t startOff : candidateOffsets) {
            if (startOff >= data.size()) continue;
            CredHistEntry testEntry{};
            if (ParseEntryAt(data, startOff, testEntry)) {
                validOffset = startOff;
                break;
            }
        }

        if (validOffset == std::string::npos) return entries;

        size_t offset = validOffset;
        while (offset < data.size()) {
            CredHistEntry entry{};
            if (!ParseEntryAt(data, offset, entry)) break;
            entries.push_back(entry);

            if (entry.dwNextLinkSize > 0) {
                offset += entry.dwNextLinkSize;
            } else {
                size_t currentEntrySize = 68 + entry.sid.size() + entry.encrypted.size();
                currentEntrySize = (currentEntrySize + 3) & ~3;
                offset += currentEntrySize;
            }
            
            if (offset <= (size_t)(offset - (entry.dwNextLinkSize > 0 ? entry.dwNextLinkSize : 1))) break;
        }

        return entries;
    }

    static const DWORD CALG_SHA1_ALG   = 0x00008004;
    static const DWORD CALG_SHA512_ALG = 0x0000800E;
    static const DWORD CALG_3DES_ALG   = 0x00006603;
    static const DWORD CALG_AES_128_ALG= 0x0000660e;
    static const DWORD CALG_AES_256_ALG= 0x00006610;

    inline std::vector<BYTE> PBKDF2(const std::vector<BYTE>& password,
                                    const BYTE* salt, size_t saltLen,
                                    DWORD iterations, size_t keyLen,
                                    const wchar_t* hashAlg) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        if (BCryptOpenAlgorithmProvider(&hAlg, hashAlg, nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0) return {};

        std::vector<BYTE> key(keyLen);
        NTSTATUS status = BCryptDeriveKeyPBKDF2(
            hAlg,
            (PUCHAR)password.data(), (ULONG)password.size(),
            (PUCHAR)salt, (ULONG)saltLen,
            iterations,
            key.data(), (ULONG)keyLen, 0);

        BCryptCloseAlgorithmProvider(hAlg, 0);
        return (status == 0) ? key : std::vector<BYTE>{};
    }

    inline std::vector<BYTE> DecryptAES(const std::vector<BYTE>& key,
                                        const BYTE* iv,
                                        const std::vector<BYTE>& ciphertext) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        std::vector<BYTE> out(ciphertext.size());

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, nullptr, 0) != 0)
            return {};
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        ULONG outLen = 0;
        std::vector<BYTE> ivCopy(iv, iv + 16);
        NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
                                        nullptr, ivCopy.data(), 16, out.data(), (ULONG)out.size(),
                                        &outLen, 0);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) return {};
        out.resize(outLen);
        return out;
    }

    inline std::vector<BYTE> Decrypt3DES(const std::vector<BYTE>& key,
                                         const BYTE* iv,
                                         const std::vector<BYTE>& ciphertext) {
        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_KEY_HANDLE hKey = nullptr;
        std::vector<BYTE> out(ciphertext.size());

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_3DES_ALGORITHM, nullptr, 0) != 0)
            return {};
        BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                          (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                          sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

        if (BCryptGenerateSymmetricKey(hAlg, &hKey, nullptr, 0,
                                       (PUCHAR)key.data(), (ULONG)key.size(), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        ULONG outLen = 0;
        std::vector<BYTE> ivCopy(iv, iv + 8);
        NTSTATUS status = BCryptDecrypt(hKey, (PUCHAR)ciphertext.data(), (ULONG)ciphertext.size(),
                                        nullptr, ivCopy.data(), 8, out.data(), (ULONG)out.size(),
                                        &outLen, 0);

        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);

        if (status != 0) return {};
        out.resize(outLen);
        return out;
    }

    inline bool ValidatePKCS7(const std::vector<BYTE>& plain, size_t expectedLen) {
        if (plain.size() < expectedLen) return false;
        size_t padLen = plain.size() - expectedLen;
        if (padLen == 0 || padLen > 16) return false;

        BYTE padVal = plain.back();
        if (padVal == 0 || padVal > padLen) return false;

        for (size_t i = plain.size() - padVal; i < plain.size(); ++i) {
            if (plain[i] != padVal) return false;
        }
        return true;
    }

    // Funkcja HMAC wyprowadzająca klucz z uwzględnieniem SID użytkownika (Wymóg DPAPI)
    inline std::vector<BYTE> DerivePasswordHashWithSID(const std::vector<BYTE>& pwdHash, const std::vector<BYTE>& sidBytes, const wchar_t* hashAlg) {
        if (sidBytes.empty()) return pwdHash;

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::vector<BYTE> derived(20);
        if (wcscmp(hashAlg, BCRYPT_SHA512_ALGORITHM) == 0) {
            derived.resize(64);
        }

        if (BCryptOpenAlgorithmProvider(&hAlg, hashAlg, nullptr, BCRYPT_ALG_HANDLE_HMAC_FLAG) != 0)
            return pwdHash;

        DWORD cbHashObject = 0, cbData = 0;
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(DWORD), &cbData, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return pwdHash;
        }

        std::vector<BYTE> hashObject(cbHashObject);
        if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, (PUCHAR)pwdHash.data(), (ULONG)pwdHash.size(), 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return pwdHash;
        }

        if (BCryptHashData(hHash, (PUCHAR)sidBytes.data(), (ULONG)sidBytes.size(), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return pwdHash;
        }

        if (BCryptFinishHash(hHash, derived.data(), (ULONG)derived.size(), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return pwdHash;
        }

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return derived;
    }

    inline bool DecryptEntry(CredHistEntry& entry, const std::vector<BYTE>& pwdHash) {
        const wchar_t* hashName = (entry.algHash == CALG_SHA1_ALG) ? BCRYPT_SHA1_ALGORITHM
                                                                   : BCRYPT_SHA512_ALGORITHM;

        // Domieszanie SID użytkownika do hasha hasła za pomocą HMAC
        std::vector<BYTE> effectiveHash = DerivePasswordHashWithSID(pwdHash, entry.sid, hashName);

        DWORD keyLen = 24;
        if (entry.algCrypt == CALG_AES_256_ALG) keyLen = 32;
        else if (entry.algCrypt == CALG_AES_128_ALG) keyLen = 16;
        else if (entry.algCrypt == CALG_3DES_ALG) keyLen = 24;

        std::vector<BYTE> derived = PBKDF2(effectiveHash, entry.salt, 16,
                                            entry.dwPbkdf2IterationCount,
                                            keyLen + 16, hashName);
        if (derived.size() < keyLen + 16) return false;

        std::vector<BYTE> cryptKey(derived.begin(), derived.begin() + keyLen);
        std::vector<BYTE> iv(derived.begin() + keyLen, derived.end());

        std::vector<BYTE> plain;
        if (entry.algCrypt == CALG_AES_256_ALG || entry.algCrypt == CALG_AES_128_ALG)
            plain = DecryptAES(cryptKey, iv.data(), entry.encrypted);
        else if (entry.algCrypt == CALG_3DES_ALG)
            plain = Decrypt3DES(cryptKey, iv.data(), entry.encrypted);
        else
            return false;

        if (plain.empty()) return false;

        size_t expectedPlainLen = entry.dwShaHashSize + entry.dwNtHashSize;
        if (!ValidatePKCS7(plain, expectedPlainLen)) {
            return false;
        }

        entry.decryptedSha.assign(plain.begin(), plain.begin() + entry.dwShaHashSize);
        entry.decryptedNt.assign(plain.begin() + entry.dwShaHashSize,
                                 plain.begin() + expectedPlainLen);

        return true;
    }

    inline std::string FormatHashLine(const CredHistEntry& e) {
        std::ostringstream oss;
        oss << "$credhist$"
            << std::dec << e.dwPbkdf2IterationCount << "$"
            << std::hex << e.algHash << "$"
            << std::hex << e.algCrypt << "$"
            << ToHex(e.salt, 16) << "$"
            << ToHex(e.encrypted.data(), e.encrypted.size());
        return oss.str();
    }

    inline std::vector<BYTE> ComputeSHA1(const std::string& password) {
        if (password.empty()) return {};
        
        int wcharLen = MultiByteToWideChar(CP_UTF8, 0, password.c_str(), (int)password.size(), nullptr, 0);
        std::wstring wpassword;
        if (wcharLen > 0) {
            wpassword.resize(wcharLen);
            MultiByteToWideChar(CP_UTF8, 0, password.c_str(), (int)password.size(), wpassword.data(), wcharLen);
        } else {
            wcharLen = MultiByteToWideChar(CP_ACP, 0, password.c_str(), (int)password.size(), nullptr, 0);
            if (wcharLen <= 0) return {};
            wpassword.resize(wcharLen);
            MultiByteToWideChar(CP_ACP, 0, password.c_str(), (int)password.size(), wpassword.data(), wcharLen);
        }

        BCRYPT_ALG_HANDLE hAlg = nullptr;
        BCRYPT_HASH_HANDLE hHash = nullptr;
        std::vector<BYTE> sha1(20);

        if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, nullptr, 0) != 0)
            return {};

        DWORD cbHashObject = 0, cbData = 0;
        if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbHashObject, sizeof(DWORD), &cbData, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        std::vector<BYTE> hashObject(cbHashObject);
        if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), cbHashObject, nullptr, 0, 0) != 0) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        if (BCryptHashData(hHash, (PUCHAR)wpassword.data(), (ULONG)(wpassword.size() * sizeof(wchar_t)), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        if (BCryptFinishHash(hHash, sha1.data(), (ULONG)sha1.size(), 0) != 0) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return sha1;
    }

    inline void Run(const std::string& password = "") {
        std::wstring path = GetCredHistPath();
        if (path.empty()) {
            std::cerr << "[-] Could not resolve CREDHIST path.\n";
            return;
        }

        std::wcout << L"[*] CREDHIST path: " << path << L"\n";
        auto data = ReadFileBytes(path);
        if (data.empty()) {
            std::cerr << "[-] CREDHIST file is empty or unreadable.\n";
            return;
        }
        std::cout << "[*] File size: " << data.size() << " bytes\n";

        auto entries = ParseCredHist(data);
        if (entries.empty()) {
            std::cerr << "[-] No valid CREDHIST entries found (malformed or unsupported version).\n";
            return;
        }
        std::cout << "[+] Found " << entries.size() << " history entries.\n\n";

        std::cout << "[*] Offline hash lines (feed to Hashcat -m 15920 / -m 15930):\n";
        for (size_t i = 0; i < entries.size(); ++i)
            std::cout << "  [" << i << "] " << FormatHashLine(entries[i]) << "\n";

        if (!password.empty()) {
            std::cout << "\n[*] Attempting to decrypt chain with supplied password...\n";
            std::vector<BYTE> currentKey = ComputeSHA1(password);
            if (currentKey.empty()) {
                std::cerr << "[-] Failed to compute SHA1 of password.\n";
                return;
            }

            for (size_t i = 0; i < entries.size(); ++i) {
                if (!DecryptEntry(entries[i], currentKey)) {
                    std::cerr << "  [-] Failed to decrypt entry [" << i << "]. Wrong password or corrupted data.\n";
                    break;
                }

                std::cout << "  [+] Entry [" << i << "] decrypted successfully.\n";
                std::cout << "      SHA1: " << ToHex(entries[i].decryptedSha.data(), entries[i].decryptedSha.size()) << "\n";
                std::cout << "      NTLM: " << ToHex(entries[i].decryptedNt.data(), entries[i].decryptedNt.size()) << "\n";

                currentKey = entries[i].decryptedSha;
            }
        } else {
            std::cout << "\n[*] Tip: To walk the full chain, provide the current password using --credhist-pass <password>.\n";
        }
    }

} // namespace CredHistDump

#endif // CREDHIST_DUMP_H