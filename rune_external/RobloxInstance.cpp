//
// Created by Dottik on 19/11/2023.
//
#include "RobloxInstance.hpp"
#include <iostream>

const char *RobloxInstance::GetName() {
   auto ptr = this->m_pRune->ReadQword(this->m_rpInstance + NAME_OFFSET);

    if (ptr == oxorany(0x0)) {
         return "???";
    }

    auto fl = this->m_pRune->ReadQword(ptr + oxorany(0x18));
    if (fl == oxorany(0x1F)) {
        ptr = this->m_pRune->ReadQword(ptr);
    }

    auto str = this->m_pRune->ReadString(this->m_pRune->ReadQword(ptr)); 

    if (str != nullptr && str != "NO_ACCESS") {
        return str;
    }
    
    return this->m_pRune->ReadString(ptr);
}


const char *RobloxInstance::GetInstanceClassName() {
    auto rpName = this->m_pRune->ReadQword(this->m_rpInstance + oxorany(0x18));
    auto rpClassName = this->m_pRune->ReadQword(rpName + oxorany(0x8));

    if (rpClassName == oxorany(0x0)) {
        return "Unknown";
    } else {
        auto isNestedPointer = this->m_pRune->ReadQword(rpClassName + oxorany(0x18));
        if (isNestedPointer == oxorany(0x1F)) {
            rpClassName = this->m_pRune->ReadQword(rpClassName);
        }
        return this->m_pRune->ReadString(rpClassName);
    }
}

RobloxInstance RobloxInstance::GetParent() {
    return {this->m_pRune, this->m_rpInstance + PARENT_OFFSET};
}

DWORD64 RobloxInstance::CalculateNameOffset() {
    auto dataModel = this->m_pRune->GetDataModel();
    for (auto i = 1; i < 11; i++) {
        auto address = dataModel - 8 * i;
        address = this->m_pRune->ReadQword(address);
        auto str = this->m_pRune->ReadString(address, 5);
        if (str == "Game") {
            return dataModel - address; // Name offset
        }
    }
    return -1;
}


DWORD64 RobloxInstance::CalculateChildrenOffset() {
    for (DWORD64 i = oxorany(0x10); i < oxorany(0x200) + oxorany(8); i += oxorany(8)) {
        auto pChild = this->m_pRune->GetDataModel() + i;
        DWORD64 childrenStart = this->m_pRune->ReadQword(pChild);
        DWORD64 childrenEnd = this->m_pRune->ReadQword(pChild + oxorany(8));

        if (childrenStart != oxorany(0x0) && childrenEnd != oxorany(0x0) &&
            childrenEnd > childrenStart &&
            childrenEnd - childrenStart > oxorany(0x1) &&
            childrenEnd - childrenStart < oxorany(0x1000)
                ) {
            return i;
        }
    }
    return -1;
}

std::vector<RobloxInstance> RobloxInstance::GetChildren() {
    auto childOff = CalculateChildrenOffset();
    auto instanceChildren = this->m_rpInstance + childOff;
    DWORD64 childrenStart = this->m_pRune->ReadQword(instanceChildren);
    DWORD64 childrenEnd = this->m_pRune->ReadQword(instanceChildren + oxorany(8));

    // TODO: Error handling

    std::vector<RobloxInstance> instances{};
    DWORD64 currentChild = childrenStart;
    while (currentChild < childrenEnd) {
        instances.emplace_back(this->m_pRune, this->m_pRune->ReadQword(currentChild));
        currentChild += oxorany(0x10);
    }
    return instances;
}

std::optional<RobloxInstance> RobloxInstance::FindFirstChild(const char *szInstanceName) {
    auto children = this->GetChildren();
    for (auto &child: children) {
        if (child.GetName() == szInstanceName)
            return child;
    }
    return {};
}

std::uintptr_t RobloxInstance::GetAddress() const {
    return this->m_rpInstance;
}
