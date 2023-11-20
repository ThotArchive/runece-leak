//
// Created by Dottik on 19/11/2023.
//
#include <Windows.h>
#include <TlHelp32.h>
#include "Utilities.hpp"
#include "oxorany.hpp"
#include "RobloxInstance.hpp"
#include "Rune.hpp"
#include <string>
#include <iostream>
#include <sstream>
#include <cstring>

[[maybe_unused]] bool Utilities::IsProcessActive(const wchar_t *szProcessName) {
    // Windows handle of process
    HWND hWnd = FindWindowW(nullptr, szProcessName);
    if (hWnd == INVALID_HANDLE_VALUE || hWnd == nullptr)
        return false;
    return GetForegroundWindow() == hWnd;
}

[[maybe_unused]] DWORD Utilities::FindProcessId(const wchar_t *szProcessName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return oxorany(-1);
    }


    PROCESSENTRY32W pEntry32 = {};
    pEntry32.dwSize = oxorany(sizeof(pEntry32));
    DWORD pid = oxorany(-1);
    if (Process32FirstW(hSnapshot, &pEntry32)) {
        do {
            if (_wcsicmp(pEntry32.szExeFile, szProcessName) == 0) {
                pid = pEntry32.th32ProcessID;
                goto find_process_id_cleanup;
            }

        } while (Process32NextW(hSnapshot, &pEntry32));
    }

    find_process_id_cleanup:
    CloseHandle(hSnapshot);

    return pid;
}

[[maybe_unused]] std::wstring Utilities::GetUsername() {
    wchar_t username[256];
    DWORD usernameLen = sizeof(username);
    GetUserNameW(username, &usernameLen);
    return username;
}

[[maybe_unused]] std::wstring Utilities::ToHex(DWORD64 num) {
    std::wstringstream stream{};
    stream << std::hex << num;
    return stream.str();
}

std::optional<RobloxInstance> Utilities::GetService(Rune *rune, const char *szServiceName) {
    RobloxInstance instance{rune, rune->GetDataModel()};
    auto children = instance.GetChildren();

    for (auto child: children) {
        if (strcmp(szServiceName, child.GetInstanceClassName()) == 0) { // Made by https://chat.openai.com/
            return child;
        }
    }

    return {};
}
