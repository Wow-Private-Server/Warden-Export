#include "WardenExport.h"
DWORD WINAPI OnAttch(LPVOID)
{

    AllocConsole();


    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD consoleMode;
    GetConsoleMode(hConsole, &consoleMode);
    consoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hConsole, consoleMode);

    FILE* fp;
    freopen_s(&fp, "CONOUT$", "w", stdout);
    freopen_s(&fp, "CONIN$", "r", stdin);
    freopen_s(&fp, "CONOUT$", "w", stderr);
    // Set title
    SetConsoleTitleA("Warden Export Debug Console");

    std::cout << "\033[38;5;46m" << R"(
__        __            _              _____                       _   
\ \      / /_ _ _ __ __| | ___ _ __   | ____|_  ___ __   ___  _ __| |_ 
 \ \ /\ / / _` | '__/ _` |/ _ \ '_ \  |  _| \ \/ / '_ \ / _ \| '__| __|
  \ V  V / (_| | | | (_| |  __/ | | | | |___ >  <| |_) | (_) | |  | |_ 
   \_/\_/ \__,_|_|  \__,_|\___|_| |_| |_____/_/\_\ .__/ \___/|_|   \__|
                                                  |_|                    
)" << "\033[0m" << std::endl;

    std::cout << "\033[38;5;33m-------------------------------------------------------------------------------------------------\033[0m" << std::endl;
    std::cout << "\033[38;5;226mMade by TechMecca * Github https://github.com/TechMecca * Discord https://discord.gg/qwXEEZ4whU\033[0m" << std::endl;
    std::cout << "\033[38;5;33m-------------------------------------------------------------------------------------------------\033[0m" << std::endl;

    // Console messages
    std::cout << "\033[38;5;46m[+] Console Ready\033[0m" << std::endl;
    std::cout << "\033[38;5;46m[+] Initializing Hooks...\033[0m" << std::endl;

    if (WardenExport::Hook())
    {
        std::cout << "\033[38;5;46m[+] LoadWardenModule Hooked Successfully!\033[0m" << std::endl;
    }
    else
    {
        std::cout << "\033[38;5;196m[-] Failed to hook LoadWardenModule!\033[0m" << std::endl;
        return 0;
    }

    return 1;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls(hModule);
        if (HANDLE h = CreateThread(nullptr, 0, OnAttch, nullptr, 0, nullptr))
            CloseHandle(h);
        break;

    case DLL_PROCESS_DETACH:

        break;
    }

    return TRUE;
}

