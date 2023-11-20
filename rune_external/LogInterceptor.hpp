//
// Created by Dottik on 19/11/2023.
//

#pragma once

#include <vector>
#include <filesystem>

/// Intercepts Roblox's Logging to obtain the DataModel, Replicator, etc addresses.
class LogInterceptor {
public:
    [[maybe_unused]] static std::vector<std::filesystem::path> GetRobloxFileLogs();

    [[maybe_unused]] static std::filesystem::path GetLastestLog();

    [[maybe_unused]] static std::wstring GetLastestLogPath();
};

