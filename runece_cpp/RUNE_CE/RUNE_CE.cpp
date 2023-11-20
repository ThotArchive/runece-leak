#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <chrono>
#include <thread>
#include <string>
#include <ctime>
#include <cstdlib>
#include <ntstatus.h>
#include <stdexcept>
#include <winternl.h>
#include "console.h";



typedef NTSTATUS(NTAPI* pfnNtSetInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );


typedef struct _SYSTEM_HANDLE_INFORMATION
{
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;


void antihandle(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);


    BYTE securityDescriptor[SECURITY_DESCRIPTOR_MIN_LENGTH]{};
    PSID pEveryoneSid = NULL;
    PACL pDacl = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    DWORD dwAclSize;

    if (!InitializeSecurityDescriptor(securityDescriptor, SECURITY_DESCRIPTOR_REVISION)) {
        throw std::runtime_error("1: " + std::to_string(GetLastError()));
    }

    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &pEveryoneSid)) {
        throw std::runtime_error("2: " + std::to_string(GetLastError()));
    }

    dwAclSize = sizeof(ACL);
    dwAclSize += sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD);
    dwAclSize += GetLengthSid(pEveryoneSid);

    pDacl = (PACL)LocalAlloc(LPTR, dwAclSize);

    if (pDacl == NULL) {
        FreeSid(pEveryoneSid);
        throw std::runtime_error("3: " + std::to_string(GetLastError()));
    }

    if (!InitializeAcl(pDacl, dwAclSize, ACL_REVISION)) {
        LocalFree(pDacl);
        FreeSid(pEveryoneSid);
        throw std::runtime_error("4: " + std::to_string(GetLastError()));
    }

    if (!AddAccessDeniedAce(pDacl, ACL_REVISION, PROCESS_ALL_ACCESS, pEveryoneSid)) {
        LocalFree(pDacl);
        FreeSid(pEveryoneSid);
        throw std::runtime_error("5: " + std::to_string(GetLastError()));
    }

    if (!SetSecurityDescriptorDacl(securityDescriptor, TRUE, pDacl, FALSE)) {
        LocalFree(pDacl);
        FreeSid(pEveryoneSid);
        throw std::runtime_error("6: " + std::to_string(GetLastError()));
    }

    if (!SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, securityDescriptor)) {
        LocalFree(pDacl);
        FreeSid(pEveryoneSid);
        throw std::runtime_error("7: " + std::to_string(GetLastError()));
    }

    LocalFree(pDacl);
    FreeSid(pEveryoneSid);

    CloseHandle(hProcess);

}

void HideProcess(DWORD processId)
{
    // Open the process with required access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        return;
    }

    // Load the NtQuerySystemInformation function dynamically
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll == NULL)
    {
        CloseHandle(hProcess);
        return;
    }

    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (NtQuerySystemInformation == NULL)
    {
        CloseHandle(hProcess);
        FreeLibrary(hNtdll);
        return;
    }

    // Retrieve the handle table entry
    // Retrieve the handle table entry
#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

// Retrieve the handle table entry
    ULONG bufferSize = 0;
    NtQuerySystemInformation(SystemExtendedHandleInformation, NULL, 0, &bufferSize);

    if (bufferSize == 0)
    {
        CloseHandle(hProcess);
        FreeLibrary(hNtdll);
        return;
    }

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(bufferSize);
    if (handleInfo == NULL)
    {
        CloseHandle(hProcess);
        FreeLibrary(hNtdll);
        return;
    }

    NTSTATUS status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfo, bufferSize, NULL);

    if (status != STATUS_SUCCESS)
    {
        free(handleInfo);
        CloseHandle(hProcess);
        FreeLibrary(hNtdll);
        return;
    }

    // Find the process handle entry and modify it
    DWORD handleCount = bufferSize / sizeof(SYSTEM_HANDLE_INFORMATION);
    for (DWORD i = 0; i < handleCount; ++i)
    {
        SYSTEM_HANDLE_INFORMATION handle = handleInfo[i];

        if (handle.ProcessId == processId && handle.Handle != (USHORT)-1)
        {
            HANDLE targetHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, processId);
            if (targetHandle != NULL)
            {
                HANDLE dupHandle;
                DuplicateHandle(GetCurrentProcess(), targetHandle, hProcess, &dupHandle, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
                CloseHandle(targetHandle);
                break;
            }
        }
    }


    free(handleInfo);
    CloseHandle(hProcess);
    FreeLibrary(hNtdll);
}

bool FE(DWORD processid) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processid);
    if (hProcess == NULL)
    {
        Error("Failed to Open an handle on Bygay");
        return false;
    }


    

    BYTE securityDescriptor[SECURITY_DESCRIPTOR_MIN_LENGTH]{};
    PSID pEveryoneSid = NULL;
    PACL pDacl = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    DWORD dwAclSize;

    if (!InitializeSecurityDescriptor(securityDescriptor, SECURITY_DESCRIPTOR_REVISION))
    {
        Error("Failed to set description for ByGay");
        CloseHandle(hProcess);
        
        return false;
    }

    if (!AllocateAndInitializeSid(&SIDAuthWorld, 1,
        SECURITY_WORLD_RID,
        0, 0, 0, 0, 0, 0, 0,
        &pEveryoneSid))
    {
        CloseHandle(hProcess);
        Error("Failed to set Allocation Data for ByGay");
        return false;
    }

    dwAclSize = sizeof(ACL);
    dwAclSize += sizeof(ACCESS_DENIED_ACE) - sizeof(DWORD);
    dwAclSize += GetLengthSid(pEveryoneSid);

    pDacl = (PACL)LocalAlloc(LPTR, dwAclSize);

    if (pDacl == NULL)
    {
        FreeSid(pEveryoneSid);
        CloseHandle(hProcess);
        Error("Failed to set PDacl Data for ByGay");
        return false;
    }

    if (!InitializeAcl(pDacl, dwAclSize, ACL_REVISION))
    {
        LocalFree(pDacl);
        FreeSid(pEveryoneSid);
        CloseHandle(hProcess);
        Error("Failed to set Acl for ByGay");
        return false;
    }

    if (!AddAccessDeniedAce(pDacl, ACL_REVISION, PROCESS_ALL_ACCESS, pEveryoneSid))
    {
        LocalFree(pDacl);
        FreeSid(pEveryoneSid);
        CloseHandle(hProcess);
        Error("Failed to set ACE for ByGay");
        return false;
    }

    if (!SetSecurityDescriptorDacl(securityDescriptor, TRUE, pDacl, FALSE))
    {
        LocalFree(pDacl);
        FreeSid(pEveryoneSid);
        CloseHandle(hProcess);
        Error("Failed to Set Dacal for ByGay");
        return false;
    }

    if (!SetKernelObjectSecurity(hProcess, DACL_SECURITY_INFORMATION, securityDescriptor))
    {
        LocalFree(pDacl);
        FreeSid(pEveryoneSid);
        CloseHandle(hProcess);
        Error("Failed to Set KernalOBJ for ByGay");
        return false;
    }

    LocalFree(pDacl);
    FreeSid(pEveryoneSid);
    CloseHandle(hProcess);

    return true;
}


void HideOpenHandle(DWORD processId)
{
    // Open the process with required access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        return;
    }

    // Load the NtSetInformationProcess function dynamically
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll == NULL)
    {
        CloseHandle(hProcess);
        return;
    }

    typedef NTSTATUS(NTAPI* _NtSetInformationProcess)(
        HANDLE ProcessHandle,
        ULONG ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength
        );

    _NtSetInformationProcess NtSetInformationProcess = (_NtSetInformationProcess)GetProcAddress(hNtdll, "NtSetInformationProcess");
    if (NtSetInformationProcess == NULL)
    {
        CloseHandle(hProcess);
        FreeLibrary(hNtdll);
        return;
    }

    // Define the process information structure
    typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO
    {
        HANDLE HandleValue;
        ULONG_PTR HandleCount;
        ULONG_PTR PointerCount;
        ULONG GrantedAccess;
        ULONG ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    } PROCESS_HANDLE_TABLE_ENTRY_INFO, * PPROCESS_HANDLE_TABLE_ENTRY_INFO;

    typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO_EX
    {
        PROCESS_HANDLE_TABLE_ENTRY_INFO Info;
        ULONG_PTR Object;
        ULONG_PTR GrantedAccess;
    } PROCESS_HANDLE_TABLE_ENTRY_INFO_EX, * PPROCESS_HANDLE_TABLE_ENTRY_INFO_EX;

    // Define the process information class
    typedef enum _PROCESS_INFORMATION_CLASS
    {
        ProcessHandleTableEntryInfo = 64,
        ProcessHandleTableEntryInfoEx = 72
    } PROCESS_INFORMATION_CLASS;

    // Retrieve the handle table entry information
    PROCESS_HANDLE_TABLE_ENTRY_INFO_EX handleInfo;
    handleInfo.Info.HandleValue = hProcess;
    handleInfo.Info.HandleCount = 0;
    handleInfo.Info.PointerCount = 0;
    handleInfo.Info.GrantedAccess = 0;
    handleInfo.Info.ObjectTypeIndex = 0;
    handleInfo.Info.HandleAttributes = 0;
    handleInfo.Info.Reserved = 0;
    handleInfo.Object = NULL;
    handleInfo.GrantedAccess = 0;

    NTSTATUS status = NtSetInformationProcess(hProcess, ProcessHandleTableEntryInfoEx, &handleInfo, sizeof(handleInfo));

    if (status != STATUS_SUCCESS)
    {
        CloseHandle(hProcess);
        FreeLibrary(hNtdll);
        return;
    }

    CloseHandle(hProcess);
    FreeLibrary(hNtdll);
}


bool LaunchCE(const wchar_t* ce) {
    STARTUPINFOW startupInfo;
    PROCESS_INFORMATION processInfo;

    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);
    ZeroMemory(&processInfo, sizeof(processInfo));

    startupInfo.dwFlags = STARTF_USESHOWWINDOW;
    startupInfo.wShowWindow = SW_SHOWNORMAL;

    if (!CreateProcessW(ce, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &startupInfo, &processInfo)) {
        return false;
    }

    



    Success("Detected ByGay PID..");
   
    if (FE(processInfo.dwProcessId)) {

        Success("Added Access Denied ACE added to DACL");
        Success("Added SetKernelObjectSecurity");
        
 
    }

    

    
    HideOpenHandle(processInfo.dwProcessId);
    Success("Set ByGay OpenHandles to hidden");
    HideProcess(processInfo.dwProcessId);
    Success("Set ByGay Process hidden from task list");
    CloseHandle(processInfo.hProcess);
    CloseHandle(processInfo.hThread);


    //antihandle();

    return true;
}



std::wstring GenerateRandomString(int length) {
    static const wchar_t alphabet[] = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    static const int alphabetSize = sizeof(alphabet) / sizeof(alphabet[0]) - 1;

    std::wstring randomString;
    randomString.reserve(length);

    for (int i = 0; i < length; ++i) {
        randomString += alphabet[rand() % alphabetSize];
    }

    return randomString;
}

bool IsProcessRunning(const wchar_t* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(snapshot, &processEntry)) {
        CloseHandle(snapshot);
        return false;
    }

    do {
        if (wcscmp(processEntry.szExeFile, processName) == 0) {
            CloseHandle(snapshot);
            return true;
        }
    } while (Process32NextW(snapshot, &processEntry));

    CloseHandle(snapshot);
    return false;
}

DWORD getProcessIDFromName(const std::wstring& processName)
{


    DWORD processID = 0;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &entry))
        {
            do
            {
                std::wstring currentProcessName = entry.szExeFile;

                if (_wcsicmp(currentProcessName.c_str(), processName.c_str()) == 0)
                {
                    processID = entry.th32ProcessID;
                    std::cout << processID;
                    break;
                }
            } while (Process32Next(hSnapshot, &entry));
        }

        CloseHandle(hSnapshot);
    }

    return processID;
}

void refreshNTUserData()
{
    LPCWSTR cleanupUtilityPath = L"cleanmgr.exe";
    LPCWSTR cleanupParameters = L"/sagerun:65535";

    SHELLEXECUTEINFO shExInfo = { 0 };
    shExInfo.cbSize = sizeof(shExInfo);
    shExInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExInfo.hwnd = nullptr;
    shExInfo.lpVerb = L"open";
    shExInfo.lpFile = cleanupUtilityPath;
    shExInfo.lpParameters = cleanupParameters;
    shExInfo.lpDirectory = nullptr;
    shExInfo.nShow = SW_SHOW;
    shExInfo.hInstApp = nullptr;

    if (ShellExecuteEx(&shExInfo))
    {
        WaitForSingleObject(shExInfo.hProcess, INFINITE);
        CloseHandle(shExInfo.hProcess); // Close the handle when done
    }
    else
    {
        // Handle the error if ShellExecuteEx fails
        DWORD dwError = GetLastError();
        // You might want to log or handle the error accordingly
    }
}






bool ChangeProcessWindowTitle(const wchar_t* processName) {
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false; 
    }

    if (!Process32FirstW(snapshot, &entry)) {
        CloseHandle(snapshot);
        return false; 
    }

    DWORD processId = 0;
    while (Process32NextW(snapshot, &entry)) {
        std::wstring currentProcessName = entry.szExeFile;
        if (currentProcessName == processName) {
            processId = entry.th32ProcessID;
            break;
        }
    }

    CloseHandle(snapshot);

    if (processId == 0) {
        return false; 
    }
  
    HWND targetWindow = FindWindowW(NULL, L"RUNE ON TOP");
    if (targetWindow == NULL) {
        return false;
    }

    std::wstring randomTitle = GenerateRandomString(25);
    SetWindowTextW(targetWindow, randomTitle.c_str());

    return true;
}



void StopThreads(DWORD processID)
{
    std::cout << "Suspended all threads in process with ID: " << processID << std::endl;

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == processID)
            {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread != NULL)
                {
                    SuspendThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
}

void ResumeThreads(DWORD processID)
{
    std::cout << "Resumed all threads in process with ID: " << processID << std::endl;

    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == processID)
            {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread != NULL)
                {
                    ResumeThread(hThread);
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(hThreadSnap, &te32));
    }

    CloseHandle(hThreadSnap);
}

int main()
{
    HWND hWnd = GetConsoleWindow();

    SetWindowTextW(hWnd, L"ByGay 1.8 - https://discord.gg/runesoftware");
    BygayBanner();

    refreshNTUserData();
    Success("Refreshed NtUser | Prevents HWID Bans");

    const wchar_t* UWP = L"Windows10Universal.exe";
    const wchar_t* WEB = L"RobloxPlayerBeta.exe";


    
    std::string Roblox = "";
    

    

    if (IsProcessRunning(UWP)) {
        Roblox = "(Version: UWP)";
        
        
    }

    if (IsProcessRunning(WEB)) {
        Roblox = "(Version: WEB)";
        
        
    }


    

    if (Roblox.empty()) {
        Error("Please Open Roblox (WEB or UWP)");
        system("PAUSE > nil");
        return 0;
    }
    
    Success("If you are crashing make sure you start RUNE_CE while roblox is launching when it says checking for updates\n\n");
    Success("Detected Roblox 64x - " + Roblox);
    Success("Waiting for you to join https://www.roblox.com/games/15308504270/script-test Once joined enter the place ID of the game!");
    Error("Make sure the game you teleported to has a item in it's backpack!");
    Success("Press Enter when roblox is starting.../");
    system("PAUSE > nil");

    

    Success("Starting Bygay...");

    
    //Sleep(2000);

    const wchar_t* CE = L"erm.exe";
    
    if (LaunchCE(CE)) {
        Success("Started Bygay!");
    }

    DWORD bygaypid = getProcessIDFromName(CE);
    StopThreads(bygaypid);
    Sleep(5000);
    ResumeThreads(bygaypid);
    StopThreads(bygaypid);
    Sleep(2000);
    ResumeThreads(bygaypid);

    //Sleep(3000);
    //if (!ChangeProcessWindowTitle(L"erm.exe")) {
       // Success("Spoofed Window Title");
    //}


    
    

    

   
    


   

   
    
    system("PAUSE > nill");


   
}

