//
// Created by Dottik on 19/11/2023.
//
#include <oxorany.hpp>
#include "Console.hpp"


void Console::Success(const std::wstring &str) {
    std::wcout << oxorany(L"[") << termcolor::green << oxorany(L"+") << termcolor::reset << oxorany(L"] - ") << str
               << std::endl;
}

void Console::Error(const std::wstring &str) {
    std::wcerr << oxorany(L"[") << termcolor::red << oxorany(L"!") << termcolor::reset << oxorany(L"] - ") << str
               << std::endl;
}

void Console::Warning(const std::wstring &str) {
    std::wcout << oxorany(L"[") << termcolor::yellow << oxorany(L"!") << termcolor::reset << oxorany(L"] - ") << str
               << std::endl;
}