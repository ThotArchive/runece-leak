//
// Created by Dottik on 19/11/2023.
//

#pragma once

#include <Windows.h>
#include <string>
#include <optional>
#include "Rune.hpp"
#include "RobloxInstance.hpp"

class Utilities {
public:
    [[maybe_unused]] static bool IsProcessActive(const wchar_t *processName);

    [[maybe_unused]] static unsigned long FindProcessId(const wchar_t *szProcessName);

    [[maybe_unused]] static std::wstring GetUsername();

    [[maybe_unused]] static std::wstring ToHex(DWORD64 num);

    [[maybe_unused]] static std::optional<RobloxInstance> GetService(Rune *rune, const char *szServiceName);
};


