#ifndef CREDHIST_DUMP_H
#define CREDHIST_DUMP_H

#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <iomanip>
#include <sstream>

namespace CredHistDump {

    #pragma pack(push, 1)
    struct CREDHIST_ENTRY_HEADER {
        DWORD dwVersion;
        GUID  guidLink;
        DWORD dwNextLinkSize;
        DWORD dwCredLinkType;
        DWORD algHash;
        DWORD dwPbkdf2IterationCount;
        DWORD dwSidSize;
        DWORD algCrypt;
        DWORD dwShaHashSize;
        DWORD dwNtHashSize;
        BYTE  salt[16];
    };
    #pragma pack(pop)

    inline std::string BytesToHex(const BYTE* data, size_t size) {
        std::ostringstream ss;
        for (size_t i = 0; i < size; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        return ss.str();
    }

    inline const char* AlgHashName(DWORD alg) {
        switch (alg) {
            case 0x8004: return "SHA1";
            case 0x800c: return "SHA256";
            case 0x800d: return "SHA384";
            case 0x800e: return "SHA512";
            default:     return "Unknown";
        }
    }

    inline const char* AlgCryptName(DWORD alg) {
        switch (alg) {
            case 0x6603: return "3DES";
            case 0x660e: return "AES-128";
            case 0x660f: return "AES-192";
            case 0x6610: return "AES-256";
            default:     return "Unknown";
        }
    }

    inline std::string GuidToString(const GUID& g) {
        char buf[64];
        snprintf(buf, sizeof(buf),
                 "{%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                 g.Data1, g.Data2, g.Data3,
                 g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
                 g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
        return std::string(buf);
    }

    // Check if entry header at `offset` looks plausible.
    inline bool IsPlausibleEntry(const std::vector<BYTE>& data, size_t offset) {
        if (offset + sizeof(CREDHIST_ENTRY_HEADER) > data.size()) return false;

        auto* hdr = reinterpret_cast<const CREDHIST_ENTRY_HEADER*>(&data[offset]);

        if (hdr->dwVersion != 1) return false;
        if (hdr->dwSidSize == 0 || hdr->dwSidSize > 1024) return false;
        if (hdr->dwShaHashSize > 256 || hdr->dwNtHashSize > 256) return false;
        if (hdr->dwPbkdf2IterationCount > 10000000) return false;

        // Check that payload fits.
        size_t payloadEnd = offset + sizeof(CREDHIST_ENTRY_HEADER)
                          + hdr->dwSidSize + hdr->dwShaHashSize + hdr->dwNtHashSize;
        if (payloadEnd > data.size()) return false;

        // Check hash algorithm is known.
        if (hdr->algHash != 0x8004 && hdr->algHash != 0x800c &&
            hdr->algHash != 0x800d && hdr->algHash != 0x800e) return false;

        // Check crypt algorithm is known.
        if (hdr->algCrypt != 0x6603 && hdr->algCrypt != 0x660e &&
            hdr->algCrypt != 0x660f && hdr->algCrypt != 0x6610) return false;

        return true;
    }

    inline void ParseEntry(const std::vector<BYTE>& data, size_t offset, int idx) {
        auto* hdr = reinterpret_cast<const CREDHIST_ENTRY_HEADER*>(&data[offset]);

        std::cout << "\n  --- Entry " << idx << " (offset " << offset << ") ---\n";
        std::cout << "    Version:         0x" << std::hex << hdr->dwVersion << std::dec << "\n";
        std::cout << "    GUID:            " << GuidToString(hdr->guidLink) << "\n";
        std::cout << "    NextLinkSize:    " << hdr->dwNextLinkSize << "\n";
        std::cout << "    CredLinkType:    " << hdr->dwCredLinkType << "\n";
        std::cout << "    PBKDF2 iters:    " << hdr->dwPbkdf2IterationCount << "\n";
        std::cout << "    Hash algorithm:  0x" << std::hex << hdr->algHash << std::dec
                  << " (" << AlgHashName(hdr->algHash) << ")\n";
        std::cout << "    Crypt algorithm: 0x" << std::hex << hdr->algCrypt << std::dec
                  << " (" << AlgCryptName(hdr->algCrypt) << ")\n";
        std::cout << "    Salt:            " << BytesToHex(hdr->salt, 16) << "\n";
        std::cout << "    SID size:        " << hdr->dwSidSize << "\n";
        std::cout << "    SHA hash size:   " << hdr->dwShaHashSize << "\n";
        std::cout << "    NTLM hash size:  " << hdr->dwNtHashSize << "\n";

        size_t payloadOffset = offset + sizeof(CREDHIST_ENTRY_HEADER);

        if (hdr->dwSidSize > 0 && payloadOffset + hdr->dwSidSize <= data.size()) {
            std::cout << "    SID:             "
                      << BytesToHex(&data[payloadOffset], hdr->dwSidSize) << "\n";
        }
        payloadOffset += hdr->dwSidSize;

        if (hdr->dwShaHashSize > 0 && payloadOffset + hdr->dwShaHashSize <= data.size()) {
            std::cout << "    Encrypted SHA:   "
                      << BytesToHex(&data[payloadOffset], hdr->dwShaHashSize) << "\n";
        }
        payloadOffset += hdr->dwShaHashSize;

        if (hdr->dwNtHashSize > 0 && payloadOffset + hdr->dwNtHashSize <= data.size()) {
            std::cout << "    Encrypted NTLM:  "
                      << BytesToHex(&data[payloadOffset], hdr->dwNtHashSize) << "\n";
        }
    }

    inline void Dump() {
        std::cout << "\n=== CREDHIST (DPAPI Password History) ===\n";

        wchar_t* appData = nullptr;
        if (SHGetKnownFolderPath(FOLDERID_RoamingAppData, 0, nullptr, &appData) != S_OK) {
            std::cout << "[-] Cannot resolve APPDATA.\n";
            return;
        }
        std::wstring credhistPath = std::wstring(appData) + L"\\Microsoft\\Protect\\CREDHIST";
        CoTaskMemFree(appData);

        std::ifstream f(credhistPath.c_str(), std::ios::binary);
        if (!f.is_open()) {
            std::cout << "[-] CREDHIST file not found.\n";
            return;
        }

        std::vector<BYTE> data((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
        f.close();

        std::cout << "[+] CREDHIST size: " << data.size() << " bytes\n";

        if (data.size() < 16) {
            std::cout << "[-] File too small.\n";
            return;
        }

        // Dump first 64 bytes as diagnostic.
        std::cout << "[i] First 32 bytes: " << BytesToHex(data.data(), 32) << "\n";

        // Scan for entries: check every 4-byte-aligned offset for a plausible entry.
        int found = 0;
        size_t offset = 0;
        size_t nextExpected = 0;

        while (offset + sizeof(CREDHIST_ENTRY_HEADER) <= data.size()) {
            if (IsPlausibleEntry(data, offset)) {
                found++;
                ParseEntry(data, offset, found);

                auto* hdr = reinterpret_cast<const CREDHIST_ENTRY_HEADER*>(&data[offset]);

                if (hdr->dwNextLinkSize == 0) {
                    std::cout << "\n  [i] End of chain (NextLinkSize = 0).\n";
                    break;
                }
                nextExpected = offset + hdr->dwNextLinkSize;

                // Jump to expected next link, or scan further if that fails.
                if (nextExpected + sizeof(CREDHIST_ENTRY_HEADER) <= data.size() &&
                    IsPlausibleEntry(data, nextExpected)) {
                    offset = nextExpected;
                    continue;
                }
            }
            offset += 4;
        }

        if (found == 0) {
            std::cout << "[-] No valid entries found.\n";
            std::cout << "[i] Dumping first 128 bytes for manual analysis:\n";
            size_t n = (data.size() < 128) ? data.size() : 128;
            std::cout << "    " << BytesToHex(data.data(), n) << "\n";
        } else {
            std::cout << "\n[i] Total entries parsed: " << found << "\n";
        }

        std::cout << "[i] For Hashcat $credhist$ output: DPAPISnoop.exe\n";
        std::cout << "[i] Hashcat: -m 15920 (3DES) / -m 15930 (AES-256)\n";
    }
}

#endif