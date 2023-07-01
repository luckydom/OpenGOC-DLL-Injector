#include <Windows.h>
#include <iostream>

// Function to inject the DLL into the target process
bool InjectDLL(DWORD targetProcessId, const char* dllPath)
{
    // Open the target process
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, targetProcessId);
    if (hProcess == NULL)
    {
        std::cout << "Failed to open the target process." << std::endl;
        return false;
    }

    // Calculate the size of the DLL path
    size_t dllPathSize = strlen(dllPath) + 1;

    // Allocate memory in the target process to store the DLL path
    LPVOID remoteMemory = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT, PAGE_READWRITE);
    if (remoteMemory == NULL)
    {
        std::cout << "Failed to allocate memory in the target process." << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path into the allocated memory
    if (!WriteProcessMemory(hProcess, remoteMemory, dllPath, dllPathSize, NULL))
    {
        std::cout << "Failed to write the DLL path into the target process." << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get the address of the LoadLibrary function from kernel32.dll
    LPVOID loadLibraryAddr = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    if (loadLibraryAddr == NULL)
    {
        std::cout << "Failed to get the address of the LoadLibrary function." << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create a remote thread in the target process to call the LoadLibrary function with the DLL path
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteMemory, 0, NULL);
    if (hThread == NULL)
    {
        std::cout << "Failed to create a remote thread in the target process." << std::endl;
        VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for the remote thread to finish
    WaitForSingleObject(hThread, INFINITE);

    // Clean up
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

int main_dummy()
{

    const char* targetProcessPath = "C:\\Program Files (x86)\\GOG Galaxy\\Games\\Gangsters\\gangsters.exe";  // Replace with the target process path
    const char* dllPath = "C:\\Program Files (x86)\\GOG Galaxy\\Games\\Gangsters\\v2_05_82_src\\build\\dxwnd.dll";  // Replace with your DLL path
    STARTUPINFOA startupInfo;
    PROCESS_INFORMATION processInfo;

    // Create the target process in suspended state
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    ZeroMemory(&processInfo, sizeof(processInfo));
    startupInfo.cb = sizeof(startupInfo);

    if (!CreateProcessA(targetProcessPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startupInfo, &processInfo))
    {
        std::cout << "Failed to create the target process." << std::endl;
        return 1;
    }

    // Inject the DLL into the target process
    if (InjectDLL(processInfo.dwProcessId, dllPath))
    {
        std::cout << "DLL injected successfully." << std::endl;
    }
    else
    {
        std::cout << "Failed to inject the DLL." << std::endl;
    }

    // Resume the target process
    ResumeThread(processInfo.hThread);

    // Clean up
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);

    return 0;
}