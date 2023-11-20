#include <Windows.h>
#include <iostream>
#include "Console.hpp"
#include <oxorany.hpp>
#include "Utilities.hpp"
#include "Rune.hpp"
#include <string>
#include "RobloxInstance.hpp"

int main() {
    // Grab the PID from roblox
    auto dwRobloxPid = Utilities::FindProcessId(oxorany(L"RobloxPlayerBeta.exe"));
    auto robloxStartNotInstant = false;


    if (dwRobloxPid == -1) {
        Console::Warning(oxorany(L"Waiting for Roblox (Web Client) to start..."));
        robloxStartNotInstant = true;
    }
    // Will wait till the process is open
    while (dwRobloxPid == -1) {
        dwRobloxPid = Utilities::FindProcessId(oxorany(L"RobloxPlayerBeta.exe"));
        Sleep(200);
    }


    // Wait for roblox to spawn their log file

    if (robloxStartNotInstant) {
        // Roblox was not really started "on time" per say, therefore it probably has not made its log file yet
        // and grabbing the datamodel is not going to work.

        // Wait for fucking log file (Hardcoded wait W)
        Console::Success(oxorany(L"Waiting for Roblox show it's launcher (Or start getting into the game)..."));
        Sleep(7500);
    }

    Console::Success(oxorany(L"Found Roblox process"));
    Console::Success(std::wstring(oxorany(L"Roblox PID: ")) + std::to_wstring(dwRobloxPid));
    Console::Success(oxorany(L"Initialising Rune External..."));

    Console::Success(oxorany(L"Press any key when you have entered a game... "));
    // wait for users input
    std::cin.get();

    Rune *rune = new Rune{};
    rune->Initialise();

    Console::Success(oxorany(L"Attempting to obtain DataModel..."));
    // Convert the Values to HEX
    Console::Success(std::wstring(oxorany(L"Obtained DataModel: 0x")) + Utilities::ToHex(rune->GetDataModel()));
    Console::Success(oxorany(L"Attempting to obtain PlayerService..."));
    auto PlayersService = Utilities::GetService(rune, "Players").value().GetAddress();
    const char* PlayersServiceName = RobloxInstance(rune, PlayersService).GetName();

    Console::Success(std::wstring(oxorany(L"Obtained PlayerService: 0x")) +
                     Utilities::ToHex(PlayersService));

                     
    Console::Success(
        std::wstring(oxorany(L"Obtained PlayerService Name: ")) +
        std::wstring(PlayersServiceName, PlayersServiceName + strlen(PlayersServiceName)));

    Console::Success(oxorany(L"Attempting to obtain LocalPlayer..."));

    auto LocalPlayer = rune->GetLocalPlayer(PlayersService);
    Console::Success(std::wstring(oxorany(L"Obtained LocalPlayer: 0x")) + Utilities::ToHex(LocalPlayer));

    const char* LocalPlayerName = RobloxInstance(rune, LocalPlayer).GetName();

    Console::Success(
        std::wstring(oxorany(L"Obtained LocalPlayer Name: ")) +
        std::wstring(LocalPlayerName, LocalPlayerName + strlen(LocalPlayerName)));

    std::cout << "Press any key to exit... ";
    std::cin.get();
    return 0;
}
