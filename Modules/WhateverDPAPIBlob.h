#ifndef WHATEVER_DPAPI_BLOB_H
#define WHATEVER_DPAPI_BLOB_H

#include <windows.h>
#include <wincrypt.h>
#include <sddl.h>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <shlobj.h>
#include <algorithm>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")

namespace WhateverDpapiBlob {

    // DPAPI provider signature: 01 00 00 00 D0 8C 9D DF ...
    static const BYTE kDpapiSignature[20] = {
        0x01,0x00,0x00,0x00, 0xD0,0x8C,0x9D,0xDF,
        0x01,0x15,0xD1,0x11, 0x8C,0x7A,0x00,0xC0,
        0x4F,0xC2,0x97,0xEB
    };

    inline std::vector<BYTE> ReadFileBytes(const std::wstring& path) {
        std::ifstream f(std::filesystem::path(path), std::ios::binary);
        if (!f) return {};
        return std::vector<BYTE>((std::istreambuf_iterator<char>(f)), {});
    }

    inline std::wstring GuidToWString(const GUID& g) {
        wchar_t buf[64];
        swprintf_s(buf, L"{%08lX-%04hX-%04hX-%02X%02X-%02X%02X%02X%02X%02X%02X}",
            g.Data1, g.Data2, g.Data3,
            g.Data4[0],g.Data4[1],g.Data4[2],g.Data4[3],
            g.Data4[4],g.Data4[5],g.Data4[6],g.Data4[7]);
        return buf;
    }

    inline size_t FindSignature(const std::vector<BYTE>& d) {
        for (size_t i = 0; i + 20 <= d.size(); ++i)
            if (memcmp(d.data() + i, kDpapiSignature, 20) == 0) return i;
        return SIZE_MAX;
    }

    // DPAPI blob header layout:
    //   Version(4) + ProviderGUID(16) + MasterKeyVersion(4) + MasterKeyGUID(16) + Flags(4)
    struct BlobHeader {
        DWORD version     = 0;
        GUID  provider{};
        DWORD mkVersion   = 0;
        GUID  masterKey{};
        DWORD flags       = 0;
        bool  ok          = false;
    };

    inline BlobHeader ParseHeader(const std::vector<BYTE>& blob, size_t off) {
        BlobHeader h;
        if (blob.size() < off + 44) return h;
        size_t o = off;
        memcpy(&h.version,   blob.data()+o, 4);  o += 4;
        memcpy(&h.provider,  blob.data()+o, 16); o += 16;
        memcpy(&h.mkVersion, blob.data()+o, 4);  o += 4;
        memcpy(&h.masterKey, blob.data()+o, 16); o += 16;
        memcpy(&h.flags,     blob.data()+o, 4);
        h.ok = true;
        return h;
    }

    // Returns true if the current process token is elevated (UAC).
    inline bool IsElevated() {
        HANDLE tok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
        TOKEN_ELEVATION te{};
        DWORD sz = sizeof(te);
        bool elevated = false;
        if (GetTokenInformation(tok, TokenElevation, &te, sz, &sz))
            elevated = te.TokenIsElevated != 0;
        CloseHandle(tok);
        return elevated;
    }

    // Checks whether the master key file for the given GUID exists in the current profile.
    inline bool MasterKeyExists(const GUID& mkGuid) {
        wchar_t* appdata = nullptr;
        if (FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appdata)))
            return false;
        std::wstring base = std::wstring(appdata) + L"\\Microsoft\\Protect";
        CoTaskMemFree(appdata);

        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileW((base + L"\\*").c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) return false;

        std::wstring wanted = GuidToWString(mkGuid);
        std::wstring wantedNoBrace = wanted.substr(1, wanted.size() - 2);
        bool found = false;

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            std::wstring sidDir = base + L"\\" + fd.cFileName;
            WIN32_FIND_DATAW f2;
            HANDLE h2 = FindFirstFileW((sidDir + L"\\*").c_str(), &f2);
            if (h2 == INVALID_HANDLE_VALUE) continue;
            do {
                if (std::wstring(f2.cFileName).find(wantedNoBrace) != std::wstring::npos) {
                    found = true; break;
                }
            } while (FindNextFileW(h2, &f2));
            FindClose(h2);
            if (found) break;
        } while (FindNextFileW(h, &fd));
        FindClose(h);
        return found;
    }

    inline void PrintHex(const BYTE* d, size_t n) {
        for (size_t i = 0; i < n; ++i)
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(d[i]);
        std::cout << std::dec << "\n";
    }

    inline bool LooksLikeText(const BYTE* d, size_t n) {
        for (size_t i = 0; i < n; ++i) {
            BYTE b = d[i];
            if (b == 0) return false;
            if (b < 0x20 && b != '\t' && b != '\n' && b != '\r') return false;
        }
        return true;
    }

    inline int DecryptBlobFromFile(const std::wstring& path) {
        auto file = ReadFileBytes(path);
        if (file.empty()) {
            std::cerr << "[-] File is empty or unreadable.\n";
            return 1;
        }

        std::cout << "[*] File: " << file.size() << " bytes\n";

        wchar_t uname[256]{}; DWORD ulen = 256;
        if (GetUserNameW(uname, &ulen))
            std::wcout << L"[*] Current user: " << uname << L"\n";

        std::cout << "[*] Process elevated (UAC): "
                  << (IsElevated() ? "YES" : "NO") << "\n";

        size_t sig = FindSignature(file);
        if (sig == SIZE_MAX) {
            std::cerr << "[-] DPAPI signature not found in file.\n";
            return 3;
        }
        std::cout << "[+] DPAPI signature @ offset " << sig << "\n";

        BlobHeader h = ParseHeader(file, sig);
        if (h.ok) {
            std::wcout << L"    MasterKey GUID: " << GuidToWString(h.masterKey) << L"\n";
            std::wcout << L"    Flags: 0x" << std::hex << h.flags << std::dec << L"\n";

            bool mkExists = MasterKeyExists(h.masterKey);
            std::wcout << L"    Master key file in profile: "
                       << (mkExists ? L"FOUND" : L"MISSING") << L"\n";

            if (!mkExists) {
                std::wcerr << L"    [!] This explains error 0xd — no key to verify the HMAC.\n";
            }
        }

        // Candidate blob lengths to try
        std::vector<size_t> ends{ file.size() };
        if (sig == 12 && file.size() >= 12) {
            DWORD declared = 0;
            memcpy(&declared, file.data() + 4, 4);
            size_t ex = 12 + (size_t)declared;
            if (declared > 0 && ex <= file.size() && ex != file.size())
                ends.push_back(ex);
        }

        DATA_BLOB out{};
        DWORD lastErr = 0;
        bool ok = false;
        std::string method;

        for (size_t end : ends) {
            std::vector<BYTE> blob(file.begin() + sig, file.begin() + end);
            std::cout << "\n[*] Trying blob of " << blob.size() << " bytes\n";

            auto tryFlags = [&](DWORD f, const char* name) -> bool {
                DATA_BLOB in{ (DWORD)blob.size(), blob.data() };
                if (CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, f, &out)) {
                    ok = true;
                    method = name;
                    return true;
                }
                lastErr = GetLastError();
                std::cout << "    " << name << " -> 0x"
                          << std::hex << lastErr << std::dec << "\n";
                return false;
            };

            if (tryFlags(0, "flags=0")) break;
            if (tryFlags(CRYPTPROTECT_UI_FORBIDDEN, "UI_FORBIDDEN")) break;
            if (tryFlags(CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE,
                         "LOCAL_MACHINE")) break;
        }

        if (!ok) {
            std::cerr << "\n[-] Decryption failed. Last error: 0x"
                      << std::hex << lastErr << std::dec << "\n";
            if (h.ok)
                std::wcerr << L"    Required master key: "
                           << GuidToWString(h.masterKey) << L"\n";
            std::cerr << "    Check:\n"
                         "      1) Are you running as Administrator/SYSTEM? (must be same user)\n"
                         "      2) Does the master key file exist under "
                         "%APPDATA%\\Microsoft\\Protect\\<SID>\\\n"
                         "      3) Was the blob created on a different machine/profile?\n"
                         "      4) Did the source application use optional entropy?\n";
            return 2;
        }

        std::cout << "[+] OK (" << method << "), " << out.cbData << " bytes\n";
        std::cout << "    Hex: ";
        PrintHex(out.pbData, std::min<size_t>(out.cbData, 256));
        if (out.cbData > 256) std::cout << "    ...(truncated)\n";

        if (LooksLikeText(out.pbData, out.cbData)) {
            std::string t(reinterpret_cast<char*>(out.pbData), out.cbData);
            std::cout << "    Text: " << t << "\n";
        } else {
            std::cout << "    Text: (binary data)\n";
        }

        LocalFree(out.pbData);
        return 0;
    }

} // namespace WhateverDpapiBlob

#endif // WHATEVER_DPAPI_BLOB_H