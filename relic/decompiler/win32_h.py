"""The Windows API as a header the C declaration parser reads: the types, structs and
prototypes of common kernel32 / user32 / advapi32 / ws2_32 functions.

`sigs.lookup` falls back to its prototypes (how many arguments `CreateFileA` takes, that
`VirtualAlloc` returns a pointer), and the `win32` type library (`typelibs`) imports its
structs into a project, laid out for the binary (32- or 64-bit Windows: LLP64), so
`GetSystemInfo(&si)` reads as `si.dwPageSize`. Typedefs stand for what <windows.h> uses;
a struct is named by its tag without the leading underscore (`struct SYSTEM_INFO`).
"""

WIN32_TYPES = r"""
typedef void *HANDLE;
typedef void *HMODULE;
typedef void *HINSTANCE;
typedef void *HWND;
typedef void *HKEY;
typedef void *HMENU;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef void *HDC;
typedef void *FARPROC;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef int BOOL;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned int UINT;
typedef int LONG;
typedef unsigned int ULONG;
typedef long long LONGLONG;
typedef unsigned long long ULONGLONG;
typedef size_t SIZE_T;
typedef size_t ULONG_PTR;
typedef size_t DWORD_PTR;
typedef size_t UINT_PTR;
typedef ssize_t LONG_PTR;
typedef size_t WPARAM;
typedef ssize_t LPARAM;
typedef ssize_t LRESULT;
typedef size_t SOCKET;
typedef unsigned short WCHAR;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef WCHAR *LPWSTR;
typedef const WCHAR *LPCWSTR;
typedef DWORD *LPDWORD;
typedef long long LARGE_INTEGER;
typedef DWORD ACCESS_MASK;
typedef DWORD REGSAM;
typedef LONG LSTATUS;
typedef void *WNDPROC;
typedef void *LPTHREAD_START_ROUTINE;
"""

WIN32_STRUCTS = r"""
struct SECURITY_ATTRIBUTES { DWORD nLength; LPVOID lpSecurityDescriptor; BOOL bInheritHandle; };
struct OVERLAPPED {
    ULONG_PTR Internal; ULONG_PTR InternalHigh; DWORD Offset; DWORD OffsetHigh; HANDLE hEvent;
};
struct FILETIME { DWORD dwLowDateTime; DWORD dwHighDateTime; };
struct SYSTEMTIME {
    WORD wYear; WORD wMonth; WORD wDayOfWeek; WORD wDay; WORD wHour; WORD wMinute; WORD wSecond;
    WORD wMilliseconds;
};
struct SYSTEM_INFO {
    WORD wProcessorArchitecture; WORD wReserved; DWORD dwPageSize; LPVOID lpMinimumApplicationAddress;
    LPVOID lpMaximumApplicationAddress; DWORD_PTR dwActiveProcessorMask; DWORD dwNumberOfProcessors;
    DWORD dwProcessorType; DWORD dwAllocationGranularity; WORD wProcessorLevel; WORD wProcessorRevision;
};
struct MEMORY_BASIC_INFORMATION {
    LPVOID BaseAddress; LPVOID AllocationBase; DWORD AllocationProtect; SIZE_T RegionSize; DWORD State;
    DWORD Protect; DWORD Type;
};
struct STARTUPINFOA {
    DWORD cb; LPSTR lpReserved; LPSTR lpDesktop; LPSTR lpTitle; DWORD dwX; DWORD dwY; DWORD dwXSize;
    DWORD dwYSize; DWORD dwXCountChars; DWORD dwYCountChars; DWORD dwFillAttribute; DWORD dwFlags;
    WORD wShowWindow; WORD cbReserved2; BYTE *lpReserved2; HANDLE hStdInput; HANDLE hStdOutput;
    HANDLE hStdError;
};
struct STARTUPINFOW {
    DWORD cb; LPWSTR lpReserved; LPWSTR lpDesktop; LPWSTR lpTitle; DWORD dwX; DWORD dwY; DWORD dwXSize;
    DWORD dwYSize; DWORD dwXCountChars; DWORD dwYCountChars; DWORD dwFillAttribute; DWORD dwFlags;
    WORD wShowWindow; WORD cbReserved2; BYTE *lpReserved2; HANDLE hStdInput; HANDLE hStdOutput;
    HANDLE hStdError;
};
struct PROCESS_INFORMATION { HANDLE hProcess; HANDLE hThread; DWORD dwProcessId; DWORD dwThreadId; };
struct WIN32_FIND_DATAA {
    DWORD dwFileAttributes; struct FILETIME ftCreationTime; struct FILETIME ftLastAccessTime;
    struct FILETIME ftLastWriteTime; DWORD nFileSizeHigh; DWORD nFileSizeLow; DWORD dwReserved0;
    DWORD dwReserved1; char cFileName[260]; char cAlternateFileName[14];
};
struct WIN32_FIND_DATAW {
    DWORD dwFileAttributes; struct FILETIME ftCreationTime; struct FILETIME ftLastAccessTime;
    struct FILETIME ftLastWriteTime; DWORD nFileSizeHigh; DWORD nFileSizeLow; DWORD dwReserved0;
    DWORD dwReserved1; WCHAR cFileName[260]; WCHAR cAlternateFileName[14];
};
struct CRITICAL_SECTION {
    LPVOID DebugInfo; LONG LockCount; LONG RecursionCount; HANDLE OwningThread; HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
};
struct PROCESSENTRY32 {
    DWORD dwSize; DWORD cntUsage; DWORD th32ProcessID; ULONG_PTR th32DefaultHeapID; DWORD th32ModuleID;
    DWORD cntThreads; DWORD th32ParentProcessID; LONG pcPriClassBase; DWORD dwFlags; char szExeFile[260];
};
struct POINT { LONG x; LONG y; };
struct RECT { LONG left; LONG top; LONG right; LONG bottom; };
struct MSG {
    HWND hwnd; UINT message; WPARAM wParam; LPARAM lParam; DWORD time; struct POINT pt;
};
struct WNDCLASSA {
    UINT style; WNDPROC lpfnWndProc; int cbClsExtra; int cbWndExtra; HINSTANCE hInstance; HICON hIcon;
    HCURSOR hCursor; HBRUSH hbrBackground; LPCSTR lpszMenuName; LPCSTR lpszClassName;
};
struct WNDCLASSEXA {
    UINT cbSize; UINT style; WNDPROC lpfnWndProc; int cbClsExtra; int cbWndExtra; HINSTANCE hInstance;
    HICON hIcon; HCURSOR hCursor; HBRUSH hbrBackground; LPCSTR lpszMenuName; LPCSTR lpszClassName;
    HICON hIconSm;
};
"""

WIN32_PROTOTYPES = r"""
/* kernel32: files */
HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                   struct SECURITY_ATTRIBUTES *lpSecurityAttributes, DWORD dwCreationDisposition,
                   DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
                   struct SECURITY_ATTRIBUTES *lpSecurityAttributes, DWORD dwCreationDisposition,
                   DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead,
              struct OVERLAPPED *lpOverlapped);
BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten,
               struct OVERLAPPED *lpOverlapped);
BOOL CloseHandle(HANDLE hObject);
DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh);
BOOL GetFileSizeEx(HANDLE hFile, LARGE_INTEGER *lpFileSize);
DWORD SetFilePointer(HANDLE hFile, LONG lDistanceToMove, LONG *lpDistanceToMoveHigh, DWORD dwMoveMethod);
BOOL FlushFileBuffers(HANDLE hFile);
BOOL DeleteFileA(LPCSTR lpFileName);
BOOL DeleteFileW(LPCWSTR lpFileName);
BOOL CopyFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
BOOL MoveFileA(LPCSTR lpExistingFileName, LPCSTR lpNewFileName);
BOOL CreateDirectoryA(LPCSTR lpPathName, struct SECURITY_ATTRIBUTES *lpSecurityAttributes);
BOOL RemoveDirectoryA(LPCSTR lpPathName);
DWORD GetFileAttributesA(LPCSTR lpFileName);
DWORD GetFileAttributesW(LPCWSTR lpFileName);
BOOL SetFileAttributesA(LPCSTR lpFileName, DWORD dwFileAttributes);
HANDLE FindFirstFileA(LPCSTR lpFileName, struct WIN32_FIND_DATAA *lpFindFileData);
HANDLE FindFirstFileW(LPCWSTR lpFileName, struct WIN32_FIND_DATAW *lpFindFileData);
BOOL FindNextFileA(HANDLE hFindFile, struct WIN32_FIND_DATAA *lpFindFileData);
BOOL FindNextFileW(HANDLE hFindFile, struct WIN32_FIND_DATAW *lpFindFileData);
BOOL FindClose(HANDLE hFindFile);
DWORD GetTempPathA(DWORD nBufferLength, LPSTR lpBuffer);
UINT GetTempFileNameA(LPCSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique, LPSTR lpTempFileName);
DWORD GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer);
BOOL SetCurrentDirectoryA(LPCSTR lpPathName);
DWORD GetFullPathNameA(LPCSTR lpFileName, DWORD nBufferLength, LPSTR lpBuffer, LPSTR *lpFilePart);
BOOL DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
                     LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned,
                     struct OVERLAPPED *lpOverlapped);
HANDLE CreateFileMappingA(HANDLE hFile, struct SECURITY_ATTRIBUTES *lpFileMappingAttributes, DWORD flProtect,
                          DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
LPVOID MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh,
                     DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
BOOL UnmapViewOfFile(LPCVOID lpBaseAddress);
HANDLE GetStdHandle(DWORD nStdHandle);
BOOL WriteConsoleA(HANDLE hConsoleOutput, const void *lpBuffer, DWORD nNumberOfCharsToWrite,
                   LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);
BOOL ReadConsoleA(HANDLE hConsoleInput, LPVOID lpBuffer, DWORD nNumberOfCharsToRead,
                  LPDWORD lpNumberOfCharsRead, LPVOID pInputControl);
BOOL SetConsoleTitleA(LPCSTR lpConsoleTitle);

/* kernel32: memory */
LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType,
                      DWORD flProtect);
BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL VirtualFreeEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, LPDWORD lpflOldProtect);
BOOL VirtualProtectEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect,
                      LPDWORD lpflOldProtect);
SIZE_T VirtualQuery(LPCVOID lpAddress, struct MEMORY_BASIC_INFORMATION *lpBuffer, SIZE_T dwLength);
SIZE_T VirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, struct MEMORY_BASIC_INFORMATION *lpBuffer,
                      SIZE_T dwLength);
HANDLE GetProcessHeap(void);
HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize);
BOOL HeapDestroy(HANDLE hHeap);
LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);
HANDLE LocalAlloc(UINT uFlags, SIZE_T uBytes);
HANDLE LocalFree(HANDLE hMem);
HANDLE GlobalAlloc(UINT uFlags, SIZE_T dwBytes);
HANDLE GlobalFree(HANDLE hMem);
BOOL ReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize,
                       SIZE_T *lpNumberOfBytesRead);
BOOL WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize,
                        SIZE_T *lpNumberOfBytesWritten);

/* kernel32: processes, threads, synchronisation */
BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine,
                    struct SECURITY_ATTRIBUTES *lpProcessAttributes,
                    struct SECURITY_ATTRIBUTES *lpThreadAttributes, BOOL bInheritHandles,
                    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory,
                    struct STARTUPINFOA *lpStartupInfo, struct PROCESS_INFORMATION *lpProcessInformation);
BOOL CreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine,
                    struct SECURITY_ATTRIBUTES *lpProcessAttributes,
                    struct SECURITY_ATTRIBUTES *lpThreadAttributes, BOOL bInheritHandles,
                    DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory,
                    struct STARTUPINFOW *lpStartupInfo, struct PROCESS_INFORMATION *lpProcessInformation);
HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode);
void ExitProcess(UINT uExitCode);
BOOL GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
HANDLE GetCurrentProcess(void);
DWORD GetCurrentProcessId(void);
HANDLE GetCurrentThread(void);
DWORD GetCurrentThreadId(void);
HANDLE CreateThread(struct SECURITY_ATTRIBUTES *lpThreadAttributes, SIZE_T dwStackSize,
                    LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                    LPDWORD lpThreadId);
HANDLE CreateRemoteThread(HANDLE hProcess, struct SECURITY_ATTRIBUTES *lpThreadAttributes, SIZE_T dwStackSize,
                          LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                          LPDWORD lpThreadId);
void ExitThread(DWORD dwExitCode);
DWORD ResumeThread(HANDLE hThread);
DWORD SuspendThread(HANDLE hThread);
DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DWORD WaitForMultipleObjects(DWORD nCount, const HANDLE *lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
HANDLE CreateEventA(struct SECURITY_ATTRIBUTES *lpEventAttributes, BOOL bManualReset, BOOL bInitialState,
                    LPCSTR lpName);
BOOL SetEvent(HANDLE hEvent);
BOOL ResetEvent(HANDLE hEvent);
HANDLE CreateMutexA(struct SECURITY_ATTRIBUTES *lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
BOOL ReleaseMutex(HANDLE hMutex);
HANDLE CreateSemaphoreA(struct SECURITY_ATTRIBUTES *lpSemaphoreAttributes, LONG lInitialCount,
                        LONG lMaximumCount, LPCSTR lpName);
BOOL ReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LONG *lpPreviousCount);
void InitializeCriticalSection(struct CRITICAL_SECTION *lpCriticalSection);
void EnterCriticalSection(struct CRITICAL_SECTION *lpCriticalSection);
void LeaveCriticalSection(struct CRITICAL_SECTION *lpCriticalSection);
void DeleteCriticalSection(struct CRITICAL_SECTION *lpCriticalSection);
void Sleep(DWORD dwMilliseconds);
DWORD SleepEx(DWORD dwMilliseconds, BOOL bAlertable);
HANDLE CreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID);
BOOL Process32First(HANDLE hSnapshot, struct PROCESSENTRY32 *lppe);
BOOL Process32Next(HANDLE hSnapshot, struct PROCESSENTRY32 *lppe);
BOOL DuplicateHandle(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle,
                     HANDLE *lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
BOOL CreatePipe(HANDLE *hReadPipe, HANDLE *hWritePipe, struct SECURITY_ATTRIBUTES *lpPipeAttributes,
                DWORD nSize);

/* kernel32: modules, system, errors, strings */
HMODULE LoadLibraryA(LPCSTR lpLibFileName);
HMODULE LoadLibraryW(LPCWSTR lpLibFileName);
HMODULE LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags);
BOOL FreeLibrary(HMODULE hLibModule);
FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName);
HMODULE GetModuleHandleA(LPCSTR lpModuleName);
HMODULE GetModuleHandleW(LPCWSTR lpModuleName);
DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize);
DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize);
DWORD GetLastError(void);
void SetLastError(DWORD dwErrCode);
DWORD FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer,
                     DWORD nSize, void *Arguments);
void GetSystemInfo(struct SYSTEM_INFO *lpSystemInfo);
void GetNativeSystemInfo(struct SYSTEM_INFO *lpSystemInfo);
void GetLocalTime(struct SYSTEMTIME *lpSystemTime);
void GetSystemTime(struct SYSTEMTIME *lpSystemTime);
void GetSystemTimeAsFileTime(struct FILETIME *lpSystemTimeAsFileTime);
BOOL FileTimeToSystemTime(const struct FILETIME *lpFileTime, struct SYSTEMTIME *lpSystemTime);
DWORD GetTickCount(void);
ULONGLONG GetTickCount64(void);
BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount);
BOOL QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency);
BOOL GetComputerNameA(LPSTR lpBuffer, LPDWORD nSize);
DWORD GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
BOOL SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue);
LPSTR GetCommandLineA(void);
LPWSTR GetCommandLineW(void);
UINT GetSystemDirectoryA(LPSTR lpBuffer, UINT uSize);
UINT GetWindowsDirectoryA(LPSTR lpBuffer, UINT uSize);
BOOL IsDebuggerPresent(void);
void OutputDebugStringA(LPCSTR lpOutputString);
void DebugBreak(void);
int MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte,
                        LPWSTR lpWideCharStr, int cchWideChar);
int WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar,
                        LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, BOOL *lpUsedDefaultChar);
int lstrlenA(LPCSTR lpString);
int lstrlenW(LPCWSTR lpString);
LPSTR lstrcpyA(LPSTR lpString1, LPCSTR lpString2);
LPSTR lstrcatA(LPSTR lpString1, LPCSTR lpString2);
int lstrcmpA(LPCSTR lpString1, LPCSTR lpString2);
int lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2);

/* advapi32: registry, tokens */
LSTATUS RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HKEY *phkResult);
LSTATUS RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, HKEY *phkResult);
LSTATUS RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD Reserved, LPSTR lpClass, DWORD dwOptions,
                        REGSAM samDesired, struct SECURITY_ATTRIBUTES *lpSecurityAttributes, HKEY *phkResult,
                        LPDWORD lpdwDisposition);
LSTATUS RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, BYTE *lpData,
                         LPDWORD lpcbData);
LSTATUS RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, BYTE *lpData,
                         LPDWORD lpcbData);
LSTATUS RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData,
                       DWORD cbData);
LSTATUS RegDeleteKeyA(HKEY hKey, LPCSTR lpSubKey);
LSTATUS RegDeleteValueA(HKEY hKey, LPCSTR lpValueName);
LSTATUS RegEnumKeyExA(HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcchName, LPDWORD lpReserved,
                      LPSTR lpClass, LPDWORD lpcchClass, struct FILETIME *lpftLastWriteTime);
LSTATUS RegCloseKey(HKEY hKey);
BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, HANDLE *TokenHandle);
BOOL GetUserNameA(LPSTR lpBuffer, LPDWORD pcbBuffer);

/* user32 */
int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
WORD RegisterClassA(const struct WNDCLASSA *lpWndClass);
WORD RegisterClassExA(const struct WNDCLASSEXA *lpWndClass);
HWND CreateWindowExA(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int X, int Y,
                     int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance,
                     LPVOID lpParam);
BOOL ShowWindow(HWND hWnd, int nCmdShow);
BOOL UpdateWindow(HWND hWnd);
BOOL DestroyWindow(HWND hWnd);
BOOL GetMessageA(struct MSG *lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax);
BOOL PeekMessageA(struct MSG *lpMsg, HWND hWnd, UINT wMsgFilterMin, UINT wMsgFilterMax, UINT wRemoveMsg);
BOOL TranslateMessage(const struct MSG *lpMsg);
LRESULT DispatchMessageA(const struct MSG *lpMsg);
void PostQuitMessage(int nExitCode);
LRESULT DefWindowProcA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
LRESULT SendMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
BOOL PostMessageA(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
HWND FindWindowA(LPCSTR lpClassName, LPCSTR lpWindowName);
BOOL GetWindowRect(HWND hWnd, struct RECT *lpRect);
BOOL GetClientRect(HWND hWnd, struct RECT *lpRect);
BOOL GetCursorPos(struct POINT *lpPoint);
BOOL SetWindowTextA(HWND hWnd, LPCSTR lpString);
int GetWindowTextA(HWND hWnd, LPSTR lpString, int nMaxCount);
short GetAsyncKeyState(int vKey);
HICON LoadIconA(HINSTANCE hInstance, LPCSTR lpIconName);
HCURSOR LoadCursorA(HINSTANCE hInstance, LPCSTR lpCursorName);
int wsprintfA(LPSTR lpOut, LPCSTR lpFmt, ...);

/* ws2_32 (socket, connect, send, recv... are the libc prototypes) */
int WSAStartup(WORD wVersionRequested, void *lpWSAData);
int WSACleanup(void);
int WSAGetLastError(void);
int closesocket(SOCKET s);
int ioctlsocket(SOCKET s, LONG cmd, ULONG *argp);
"""

WIN32_H = WIN32_TYPES + WIN32_STRUCTS + WIN32_PROTOTYPES

__all__ = ["WIN32_H", "WIN32_PROTOTYPES", "WIN32_STRUCTS", "WIN32_TYPES"]
