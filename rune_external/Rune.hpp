#pragma once

#include <Windows.h>
#include "LogInterceptor.hpp"


class Rune {
public:
    Rune();

    std::uintptr_t GetDataModel();

    DWORD ReadDword(std::uintptr_t address);

    const char *ReadString(std::uintptr_t address, int suspectedSize = 10000);

    BYTE ReadByte(uintptr_t address);

    DWORD64 ReadQword(uintptr_t address);

    DWORD64 ReadDword64(uintptr_t address);

    WORD ReadWord(uintptr_t address);

    void Initialise();

    HANDLE GetRobloxHandle();

    DWORD64 GetLocalPlayer(DWORD64 playerServiceAddress);

private:
    std::uintptr_t m_pDataModel;
    DWORD m_dwRobloxPid;
    HANDLE m_hRobloxProcess;
};
