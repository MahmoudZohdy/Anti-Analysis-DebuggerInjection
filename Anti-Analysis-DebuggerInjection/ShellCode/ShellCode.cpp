#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
//#include <winternl.h> <intrin.h>
#include <intrin.h>
#include "peb.h"
#include "struct.h"

__forceinline BOOL CompareAnsii(LPCSTR String1, LPCSTR String2) {
	int len1 = 0, len2 = 0;
	while (String1[len1++] != '\0') {}
	while (String2[len2++] != '\0') {}

	if (len1 != len2) {
		return FALSE;
	}
	for (int i = 0; i < len1; i++) {
		if (String1[i] != String2[i]) {
			return FALSE;
		}
	}
	return TRUE;
}

__forceinline BOOL CompareUnicode(LPWSTR String1, LPWSTR String2) {
	int len1 = 0, len2 = 0;
	while (String1[len1++] != '\0' || String1[len1++] != '\0') {}
	while (String2[len2++] != '\0' || String2[len2++] != '\0') {}

	if (len1 != len2) {
		return FALSE;
	}
	for (int i = 0; i < len1; i++) {
		if (String1[i] != String2[i]) {
			return FALSE;
		}
	}
	return TRUE;
}

__forceinline unsigned long WINAPI GetFunctionAddress(HMODULE Base, LPCSTR FunctionName)
{
	PIMAGE_DOS_HEADER pIDH;
	PIMAGE_NT_HEADERS pINH;
	PIMAGE_EXPORT_DIRECTORY pIED;

	HMODULE hModule;
	PDWORD Address, Name;
	PWORD Ordinal;

	DWORD i;

	hModule = Base;

	pIDH = (PIMAGE_DOS_HEADER)hModule;

	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}

	pINH = (PIMAGE_NT_HEADERS)((LPBYTE)hModule + pIDH->e_lfanew);

	if (pINH->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}

	if (pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
	{
		return NULL;
	}

	pIED = (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)hModule + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	Address = (PDWORD)((LPBYTE)hModule + pIED->AddressOfFunctions);
	Name = (PDWORD)((LPBYTE)hModule + pIED->AddressOfNames);

	Ordinal = (PWORD)((LPBYTE)hModule + pIED->AddressOfNameOrdinals);

	for (i = 0; i < pIED->AddressOfFunctions; i++)
	{
		if (CompareAnsii(FunctionName, (char*)hModule + Name[i]))
		{
			return (unsigned long)((LPBYTE)hModule + Address[Ordinal[i]]);
		}
	}

	return NULL;
}

__forceinline unsigned long WINAPI GetKernel32BaseAddress() {
	unsigned long baseaddress;
	__asm {
		mov eax, fs: [30h] ;
		mov eax, [eax + 0x0c]
			mov eax, [eax + 0x14]
			mov eax, [eax]
			mov eax, [eax]
			mov eax, [eax + 0x10]
			mov baseaddress, eax
	}
	return baseaddress;
}


void InitializeHook(DWORD Pid) {
	ADDRESS_TABLE* at;

	unsigned int tableaddress;
	__asm {

		call EndOfData

		STR_DEF_04(LoadLibraryA_, 'L', 'o', 'a', 'd')
		STR_DEF_04(LoadLibraryA_, 'L', 'i', 'b', 'r')
		STR_DEF_04(LoadLibraryA_, 'a', 'r', 'y', 'A')
		STR_DEF_04(LoadLibraryA_, '\0', '\0', '\0', '\0')
		STR_DEF_04(LoadLibraryA_, '\0', '\0', '\0', '\0')


		STR_DEF_04(GetProcAddress_, 'G', 'e', 't', 'P')
		STR_DEF_04(GetProcAddress_, 'r', 'o', 'c', 'A')
		STR_DEF_04(GetProcAddress_, 'd', 'd', 'r', 'e')
		STR_DEF_04(GetProcAddress_, 's', 's', '\0', '\0')
		STR_DEF_04(LoadLibraryA_, '\0', '\0', '\0', '\0')


		STR_DEF_04(WaitForDebugEventName, 'W', 'a', 'i', 't')
		STR_DEF_04(WaitForDebugEventName, 'F', 'o', 'r', 'D')
		STR_DEF_04(WaitForDebugEventName, 'e', 'b', 'u', 'g')
		STR_DEF_04(WaitForDebugEventName, 'E', 'v', 'e', 'n')
		STR_DEF_04(WaitForDebugEventName, 't', '\0', '\0', '\0')

		STR_DEF_04(VirtualProtectName, 'V', 'i', 'r', 't')
		STR_DEF_04(VirtualProtectName, 'u', 'a', 'l', 'P')
		STR_DEF_04(VirtualProtectName, 'r', 'o', 't', 'e')
		STR_DEF_04(VirtualProtectName, 'c', 't', '\0', '\0')
		STR_DEF_04(VirtualProtectName, '\0', '\0', '\0', '\0')


		STR_DEF_04(ContinueDebugEventName, 'C', 'o', 'n', 't')
		STR_DEF_04(ContinueDebugEventName, 'i', 'n', 'u', 'e')
		STR_DEF_04(ContinueDebugEventName, 'D', 'e', 'b', 'u')
		STR_DEF_04(ContinueDebugEventName, 'g', 'E', 'v', 'e')
		STR_DEF_04(ContinueDebugEventName, 'n', 't', '\0', '\0')


		STR_DEF_04(OpenThreadName, 'O', 'p', 'e', 'n')
		STR_DEF_04(OpenThreadName, 'T', 'h', 'r', 'e')
		STR_DEF_04(OpenThreadName, 'a', 'd', '\0', '\0')
		STR_DEF_04(OpenThreadName, '\0', '\0', '\0', '\0')
		STR_DEF_04(OpenThreadName, '\0', '\0', '\0', '\0')

		STR_DEF_04(GetThreadContextName, 'G', 'e', 't', 'T')
		STR_DEF_04(GetThreadContextName, 'h', 'r', 'e', 'a')
		STR_DEF_04(GetThreadContextName, 'd', 'C', 'o', 'n')
		STR_DEF_04(GetThreadContextName, 't', 'e', 'x', 't')
		STR_DEF_04(GetThreadContextName, '\0', '\0', '\0', '\0')

		STR_DEF_04(SetThreadContextName, 'S', 'e', 't', 'T')
		STR_DEF_04(SetThreadContextName, 'h', 'r', 'e', 'a')
		STR_DEF_04(SetThreadContextName, 'd', 'C', 'o', 'n')
		STR_DEF_04(SetThreadContextName, 't', 'e', 'x', 't')
		STR_DEF_04(SetThreadContextName, '\0', '\0', '\0', '\0')


		STR_DEF_04(IsWow64ProcessName, 'I', 's', 'W', 'o')
		STR_DEF_04(IsWow64ProcessName, 'w', '6', '4', 'P')
		STR_DEF_04(IsWow64ProcessName, 'r', 'o', 'c', 'e')
		STR_DEF_04(IsWow64ProcessName, 's', 's', '\0', '\0')
		STR_DEF_04(IsWow64ProcessName, '\0', '\0', '\0', '\0')



		STR_DEF_04(DebugActiveProcessName, 'D', 'e', 'b', 'u')	
		STR_DEF_04(DebugActiveProcessName, 'g', 'A', 'c', 't')
		STR_DEF_04(DebugActiveProcessName, 'i', 'v', 'e', 'P')
		STR_DEF_04(DebugActiveProcessName, 'r', 'o', 'c', 'e')
		STR_DEF_04(DebugActiveProcessName, 's', 's', '\0', '\0')




		VAR_DWORD(WaitForDebugEventfn);
		VAR_DWORD(OpenThreadfn);
		VAR_DWORD(GetThreadContextfn);
		VAR_DWORD(SetThreadContextfn);

	EndOfData:
		pop eax
			mov tableaddress, eax

	}
	at = (ADDRESS_TABLE*)tableaddress;

	unsigned long Base = GetKernel32BaseAddress();

	GetProcAddressptr  GetProcAddress_ = (GetProcAddressptr)GetFunctionAddress((HMODULE)Base, (LPCSTR)at->routines.GetProcAddress_);

	LoadLibraryAptr LoadLibraryA_ = (LoadLibraryAptr)GetFunctionAddress((HMODULE)Base, (LPCSTR)at->routines.LoadLibraryA_);

	WaitForDebugEventptr WaitForDebugEvent_ = (WaitForDebugEventptr)GetProcAddress_((HMODULE)Base, (LPCSTR)at->WaitForDebugEventName);
	ContinueDebugEventptr	ContinueDebugEvent_ = (ContinueDebugEventptr)GetProcAddress_((HMODULE)Base, (LPCSTR)at->ContinueDebugEventName);

	at->OpenThreadfn = (OpenThreadptr)GetProcAddress_((HMODULE)Base, (LPCSTR)at->OpenThreadName);
	at->GetThreadContextfn = (GetThreadContextptr)GetProcAddress_((HMODULE)Base, (LPCSTR)at->GetThreadContextName);
	at->SetThreadContextfn = (SetThreadContextptr)GetProcAddress_((HMODULE)Base, (LPCSTR)at->SetThreadContextName);

	at->WaitForDebugEventfn = WaitForDebugEvent_;
	at->ContinueDebugEventfn = ContinueDebugEvent_;

	IsWow64Processptr IsWow64Process_ = (IsWow64Processptr)GetFunctionAddress((HMODULE)Base, (LPCSTR)at->IsWow64ProcessName);

	VirtualProtectptr VirtualProtect_ = (VirtualProtectptr)GetProcAddress_((HMODULE)Base, (LPCSTR)at->VirtualProtectName);

	DebugActiveProcessptr DebugActiveProcess_ = (DebugActiveProcessptr)GetProcAddress_((HMODULE)Base, (LPCSTR)at->DebugActiveProcessName);

	DWORD OldProtect;
	BOOL ret = VirtualProtect_((BYTE*)WaitForDebugEvent_ - 7, 15, PAGE_EXECUTE_READWRITE, &OldProtect);

	BYTE CSsegmint;
	BOOL Wow64Process;
	HANDLE hCurrentProcess = (HANDLE)-1;
	ret = IsWow64Process_(hCurrentProcess, &Wow64Process);
	if (Wow64Process) {
		CSsegmint = 0x23;
	}
	else {
		CSsegmint = 0x1B;
	}


	DWORD* StartOfChange = (DWORD*)((BYTE*)WaitForDebugEvent_ - 7);

	DWORD HookFunctionAddress;
	DWORD StartScan = tableaddress;

	while (1)
	{
		DWORD* x = (DWORD*)StartScan;
		if (((BYTE*)x)[0] == 'T' && ((BYTE*)x)[1] == 'O' && ((BYTE*)x)[2] == 'T' && ((BYTE*)x)[3] == 'O') {
			HookFunctionAddress = (DWORD)x;
			break;
		}
		StartScan++;
	}

	while (1)
	{
		DWORD* x = (DWORD*)HookFunctionAddress;
		if (((BYTE*)x)[0] == 0x55 && ((BYTE*)x)[1] == 0x8B) {
			break;
		}
		HookFunctionAddress--;
	}


	BYTE x = (BYTE)((DWORD)HookFunctionAddress);
	BYTE xx = (BYTE)(((DWORD)HookFunctionAddress & 0x0000ff00) >> 8);
	BYTE xxx = (BYTE)(((DWORD)HookFunctionAddress & 0x00ff0000) >> 16);
	BYTE xxxx = (BYTE)(((DWORD)HookFunctionAddress & 0xff000000) >> 24);


	((BYTE*)StartOfChange)[0] = 0xea;
	((BYTE*)StartOfChange)[1] = x;
	((BYTE*)StartOfChange)[2] = xx;
	((BYTE*)StartOfChange)[3] = xxx;
	((BYTE*)StartOfChange)[4] = xxxx;

	((BYTE*)StartOfChange)[5] = CSsegmint;
	((BYTE*)StartOfChange)[6] = 0x00;


	//short jump
	((BYTE*)WaitForDebugEvent_)[0] = 0xeb;
	((BYTE*)WaitForDebugEvent_)[1] = 0xf7;

}

BOOL WaitForDebugEventHook(LPDEBUG_EVENT DebugEv, DWORD dwMilliseconds) {

	unsigned int tableaddress;
	__asm {

		call EndOfData

		//Function Signiture
		STR_DEF_04(Signiture, 'T', 'O', 'T', 'O');

	EndOfData:
		pop eax
		mov tableaddress, eax
	}
	ADDRESS_TABLE* at;
	while (1)
	{
		DWORD* x = (DWORD*)tableaddress;
		if (((BYTE*)x)[0] == 'L' && ((BYTE*)x)[1] == 'o' && ((BYTE*)x)[2] == 'a' && ((BYTE*)x)[3] == 'd') {
			at = (ADDRESS_TABLE*)x;
			break;
		}
		tableaddress--;
	}

	WaitForDebugEventptr newaddress = (WaitForDebugEventptr)((BYTE*)at->WaitForDebugEventfn + 2);

	DWORD status = newaddress(DebugEv, dwMilliseconds);

	if (DebugEv->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
		CONTEXT ctx;

		HANDLE hThread = at->OpenThreadfn(THREAD_ALL_ACCESS, FALSE, DebugEv->dwThreadId);
		ctx.ContextFlags = CONTEXT_ALL;
		at->GetThreadContextfn(hThread, &ctx);

		ctx.Dr7 = 0;
		ctx.Dr0 = 0;


		int a = at->SetThreadContextfn(hThread, &ctx);
		at->ContinueDebugEventfn(DebugEv->dwProcessId, DebugEv->dwThreadId, DBG_CONTINUE);
		at->WaitForDebugEventfn(DebugEv, dwMilliseconds);


	}
	return status;
}
//used for boundry only
void uselese() {}

int main()
{


	// Output shellcode to Screen,	Should remove the last ','
	DWORD size = (DWORD)uselese - (DWORD)InitializeHook;
	printf("{");
	DWORD i;
	for (i = 0; i < size; i++) {
		printf("0x%x,", ((BYTE*)InitializeHook)[i]);
	}
	printf("};");

	return 0;
}
