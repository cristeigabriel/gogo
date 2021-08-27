package gogo

import "syscall"

var (
	//	exposed
	Instance *Context

	//	local
	gKernel32 = syscall.MustLoadDLL("kernel32.dll")

	gOpenProcess = gKernel32.MustFindProc("OpenProcess")

	gCreateToolhelp32Snapshot = gKernel32.MustFindProc("CreateToolhelp32Snapshot")

	gProcess32First = gKernel32.MustFindProc("Process32First")
	gProcess32Next  = gKernel32.MustFindProc("Process32Next")

	gModule32First = gKernel32.MustFindProc("Module32First")
	gModule32Next  = gKernel32.MustFindProc("Module32Next")

	gReadProcessMemory  = gKernel32.MustFindProc("ReadProcessMemory")
	gWriteProcessMemory = gKernel32.MustFindProc("WriteProcessMemory")
)

const (
	//	open process
	kProcessAllAccess = 0x1FFFFF

	//	toolhelp snapshot
	kTh32csSnapModule   = 0x8
	kTh32csSnapModule32 = 0x10
	kTh32csSnapAll      = 0xF
)
