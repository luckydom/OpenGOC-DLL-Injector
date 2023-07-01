#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <string>
#include <psapi.h> //EnumProcessModules
#include <VersionHelpers.h>
#include <atlstr.h> // CString
#include <iostream>
#include <windows.h>
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

int getProcId(const wchar_t* target) {
    DWORD pID = 0;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    do {
        if (wcscmp(pe32.szExeFile, target) == 0) {
            CloseHandle(hSnapshot);
            pID = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));
    // CloseHandle(hSnapshot);
    return pID;
}


void InjectDLL(DWORD processId, const char* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        std::cout << "Failed to open the target process" << std::endl;
        return;
    }

    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remoteMemory == NULL) {
        std::cout << "Failed to allocate memory in the target process" << std::endl;
        CloseHandle(hProcess);
        return;
    }

    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, strlen(dllPath) + 1, NULL)) {
        std::cout << "Failed to write DLL path to the target process" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        std::cout << "Failed to get handle to kernel32.dll" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    LPTHREAD_START_ROUTINE loadLibraryA = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
    if (loadLibraryA == NULL) {
        std::cout << "Failed to get address of LoadLibraryA" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, loadLibraryA, remoteMemory, 0, NULL);
    if (hRemoteThread == NULL) {
        std::cout << "Failed to create remote thread in the target process" << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    WaitForSingleObject(hRemoteThread, INFINITE);

    DWORD exitCode;
    if (!GetExitCodeThread(hRemoteThread, &exitCode)) {
        std::cout << "Failed to get exit code of the remote thread" << std::endl;
        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    if (exitCode == 0) {
        std::cout << "Failed to load the DLL in the target process" << std::endl;
        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return;
    }

    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

int startDxWnd(void) {
    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);
    const char* targetProcessPath = "C:\\Program Files (x86)\\GOG Galaxy\\Games\\Gangsters\\v2_05_82_src\\build\\dxwnd.exe";  // Replace with the target process path
    const char* arguments = "/c:gangsters.dxw /r:0";
    if (!CreateProcessA(targetProcessPath, const_cast<LPSTR>(arguments), NULL, NULL, FALSE, 0, NULL, NULL, &startupInfo, &processInfo)) {        
        return GetLastError();
    }
    Sleep(10000); // TODO: need a better way to detect if the process is running 

    // Clean up
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    return 0;
}

int main(void) {
    int dxWndExitCode = startDxWnd();
    if (dxWndExitCode != 0) {
        std::cout << "Failed to create the target process." << std::endl;
        return dxWndExitCode;
    }
    int pID = getProcId(L"gangsters.exe");
    char dll[] = "OpenGOC.dll";
    char dllPath[MAX_PATH] = { 0 };
    GetFullPathNameA(dll, MAX_PATH, dllPath, NULL);
    printf("Injecting");
    InjectDLL(pID, dllPath);

    return 0;
}