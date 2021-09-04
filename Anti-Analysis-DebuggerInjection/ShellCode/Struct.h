#pragma once

typedef HMODULE(NTAPI* LoadLibraryAptr)(
	LPCSTR lpLibFileName
	);

typedef FARPROC(NTAPI* GetProcAddressptr)(
	HMODULE hModule,
	LPCSTR  lpProcName
	);

typedef BOOL(NTAPI* WaitForDebugEventptr)(
	LPDEBUG_EVENT lpDebugEvent,
	DWORD         dwMilliseconds
	);

typedef BOOL(NTAPI* VirtualProtectptr)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flNewProtect,
	PDWORD lpflOldProtect
	);


typedef BOOL(NTAPI* ContinueDebugEventptr)(
	DWORD dwProcessId,
	DWORD dwThreadId,
	DWORD dwContinueStatus
	);


typedef HANDLE(NTAPI* OpenThreadptr)(
	DWORD dwDesiredAccess,
	BOOL  bInheritHandle,
	DWORD dwThreadId
	);


typedef BOOL(NTAPI* GetThreadContextptr)(
	HANDLE    hThread,
	LPCONTEXT lpContext
	);


typedef BOOL(NTAPI* SetThreadContextptr)(
	HANDLE        hThread,
	const CONTEXT* lpContext
	);


typedef BOOL(NTAPI* IsWow64Processptr)(
	HANDLE hProcess,
	PBOOL  Wow64Process
	);



typedef BOOL(NTAPI* DebugActiveProcessptr)(
	DWORD dwProcessId
	);

typedef VOID(NTAPI* ShellCodeFunction)(
	DWORD dwProcessId
	);



#define SZ_FORMAT_PTR 4
#define SZ_LIB_NAME 20

#define VAR_DWORD(name) __asm _emit 0x04 __asm _emit 0x04 __asm _emit 0x04 __asm _emit 0x04
#define STR_DEF_04(name,a1,a2,a3,a4) __asm _emit a1 __asm _emit a2 __asm _emit a3 __asm _emit a4


typedef int(NTAPI* printfptr)(const char* format, ...);

#pragma pack(1)
typedef struct _USER_MODE_ADDRES_RESOLUTION {
	unsigned char LoadLibraryA_[SZ_LIB_NAME];
	unsigned char GetProcAddress_[SZ_LIB_NAME];
}USER_MODE_ADDRES_RESOLUTION;
#pragma pack()

#pragma pack(1)
typedef struct _ADDRESS_TABLE {

	USER_MODE_ADDRES_RESOLUTION routines;
	unsigned char WaitForDebugEventName[SZ_LIB_NAME];
	unsigned char VirtualProtectName[SZ_LIB_NAME];
	unsigned char ContinueDebugEventName[SZ_LIB_NAME];

	unsigned char OpenThreadName[SZ_LIB_NAME];
	unsigned char GetThreadContextName[SZ_LIB_NAME];
	unsigned char SetThreadContextName[SZ_LIB_NAME];

	unsigned char IsWow64ProcessName[SZ_LIB_NAME];

	unsigned char DebugActiveProcessName[SZ_LIB_NAME];

	WaitForDebugEventptr WaitForDebugEventfn;
	ContinueDebugEventptr ContinueDebugEventfn;
	OpenThreadptr OpenThreadfn;
	GetThreadContextptr GetThreadContextfn;
	SetThreadContextptr SetThreadContextfn;


}ADDRESS_TABLE;
#pragma pack()