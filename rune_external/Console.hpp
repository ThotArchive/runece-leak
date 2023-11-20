//
// Created by Dottik on 19/11/2023.
//
#pragma once

#include <termcolor.hpp>


class Console {
public:
    static void Success(const std::wstring &str);

    static void Warning(const std::wstring &str);

    static void Error(const std::wstring &str);
};


