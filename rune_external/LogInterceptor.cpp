//
// Created by Dottik on 19/11/2023.
//

#include "LogInterceptor.hpp"
#include "Utilities.hpp"
#include <Windows.h>

#include <oxorany.hpp>
#include <filesystem>
#include <vector>
#include <string>
#include <iostream>


std::vector<std::filesystem::path> LogInterceptor::GetRobloxFileLogs() {
    std::vector<std::filesystem::path> RobloxLog;


    std::wstring RobloxLogPath =
            oxorany(L"C:\\Users\\") + Utilities::GetUsername() +
            oxorany(L"\\AppData\\Local\\Roblox\\logs");

    for (const auto &entry: std::filesystem::directory_iterator(RobloxLogPath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".log" &&
            entry.path().filename().string().find("Player") != std::string::npos) {
            RobloxLog.push_back(entry.path());
        }
    }
    return RobloxLog;
}

std::wstring LogInterceptor::GetLastestLogPath() {
    std::vector<std::filesystem::path> files = LogInterceptor::GetRobloxFileLogs();
    if (files.empty()) {
        return L"";
    }

    std::sort(files.begin(), files.end(), [](const std::wstring &a, const std::wstring &b) {
        return std::filesystem::last_write_time(a) > std::filesystem::last_write_time(b);
    });


    return files[0].wstring().substr(files[0].wstring().find_last_of(L'\\') + 1);
}

std::filesystem::path LogInterceptor::GetLastestLog() {
    std::vector<std::filesystem::path> files = LogInterceptor::GetRobloxFileLogs();
    if (files.empty()) {
        return L"";
    }

    std::sort(files.begin(), files.end(), [](const std::wstring &a, const std::wstring &b) {
        return std::filesystem::last_write_time(a) > std::filesystem::last_write_time(b);
    });

    return files[0];
}









/*
    auto length = 0;
    auto offset = 0;
    auto strAddress = 0xDEADBEEF;
    while (*reinterpret_cast<char *>(strAddress + offset) != '\0') {
        offset += sizeof(char);
        length += 1;
    }
    char nBuf[length + 1];

    auto len_2 = 0;
    // Read the whole string again, but this time, you copy it to the buffer
    while (len_2 < length) {
        nBuf[len_2] = *reinterpret_cast<char *>(strAddress + (sizeof(char) * len_2));
        len_2 += 1;
    }
*/