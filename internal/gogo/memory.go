package gogo

//	The following is done with inspiration from:
//	https://github.com/jamesmoriarty/gomem/blob/master/internal/kernel32/kernel32.go

import (
	"fmt"
	"syscall"
	"unsafe"
)

var (
	g_kernel32 = syscall.MustLoadDLL("kernel32.dll")

	g_openProcess = g_kernel32.MustFindProc("OpenProcess")

	g_createToolhelp32Snapshot = g_kernel32.MustFindProc("CreateToolhelp32Snapshot")

	g_process32First = g_kernel32.MustFindProc("Process32First")
	g_process32Next  = g_kernel32.MustFindProc("Process32Next")

	g_module32First = g_kernel32.MustFindProc("Module32First")
	g_module32Next  = g_kernel32.MustFindProc("Module32Next")

	g_readProcessMemory  = g_kernel32.MustFindProc("ReadProcessMemory")
	g_writeProcessMemory = g_kernel32.MustFindProc("WriteProcessMemory")
)

const (
	//	open process
	PROCESS_ALL_ACCESS = 0x1FFFFF

	//	toolhelp snapshot
	TH32CS_SNAPMODULE   = 0x8
	TH32CS_SNAPMODULE32 = 0x10
	TH32CS_SNAPALL      = 0xF
)

//	process structure
type Process struct {
	name        string
	pid         uint32
	handle      uintptr
	modulesSnap uintptr
}

//	dll structure
type Dll struct {
	name string
	base *byte
	size uint32
}

//	processentry minimalized to our use case
type ProcessEntry32 struct {
	entrySize uint32
	pad1      [4]byte
	pid       uint32
	pad2      [32]byte
	name      [260]uint8
}

//	process helpers
func getPid(name string) uint32 {
	handle, _, _ := g_createToolhelp32Snapshot.Call(TH32CS_SNAPALL, 0)

	processEntry := ProcessEntry32{entrySize: 304}

	for state, _, _ := g_process32First.Call(handle, uintptr(unsafe.Pointer(&processEntry))); state != 0; state, _, _ = g_process32Next.Call(handle, uintptr(unsafe.Pointer(&processEntry))) {
		currentName := stringify(processEntry.name[:])

		if name == currentName {
			return processEntry.pid
		}
	}

	return 0
}

//	process initializer, grab 32bit process
func getProcess(name string) *Process {
	obj := Process{name: name}

	obj.pid = getPid(obj.name)

	if obj.pid == 0 {
		panic(fmt.Sprintf("Epicly failed: Failed grabbing process %s's PID (SUS!)", obj.name))
	}

	handle, _, _ := g_openProcess.Call(PROCESS_ALL_ACCESS, 0, uintptr(obj.pid))

	if handle == 0 {
		panic(fmt.Sprintf("Epicly failed: Failed grabbing handle of process %s with PID %x (IMPOSTOR!)", obj.name, obj.pid))
	}

	obj.handle = handle

	modulesSnap, _, _ := g_createToolhelp32Snapshot.Call(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32, uintptr(obj.pid))

	if handle == 0 {
		panic(fmt.Sprintf("Epicly failed: Failed grabbing modules snapshot of process %s with PID %x (IMPOSTOR!)", obj.name, obj.pid))
	}

	obj.modulesSnap = modulesSnap

	fmt.Printf("Got handle to process: %s | pid: %d\n", obj.name, obj.pid)

	return &obj
}

//	moduleentry structure
type ModuleEntry32 struct {
	entrySize uint32
	pad1      [16]byte
	base      *byte
	size      uint32
	pad2      [12]byte
	name      [256]uint8
	exeName   [260]uint8
}

//	process utilities
func (process *Process) getModule(name string) (*uint8, uint32) {
	moduleEntry := ModuleEntry32{entrySize: 568}

	for state, _, _ := g_module32First.Call(process.modulesSnap, uintptr(unsafe.Pointer(&moduleEntry))); state != 0; state, _, _ = g_module32Next.Call(process.modulesSnap, uintptr(unsafe.Pointer(&moduleEntry))) {
		currentName := stringify(moduleEntry.name[:])

		if name == currentName {
			return moduleEntry.base, moduleEntry.size
		}
	}

	return nil, 0
}

func (process *Process) readMemory(size uint32, at uintptr) unsafe.Pointer {
	var address byte
	addressPtr := unsafe.Pointer(&address)

	state, _, _ := g_readProcessMemory.Call(uintptr(process.handle), at, uintptr(addressPtr), uintptr(size))

	if state == 0 {
		panic(fmt.Sprintf("Epicly failed: RPM at %x is SUS!", at))
	}

	return addressPtr
}

func (process *Process) readMemoryDll(dll *Dll, size uint32, ptrdiff uintptr) unsafe.Pointer {
	return process.readMemory(size, uintptr(unsafe.Pointer(dll.base))+ptrdiff)
}

func (process *Process) writeMemory(into uintptr, size uint32, at uintptr) {
	addressPtr := uintptr(unsafe.Pointer(&into))
	state, _, _ := g_writeProcessMemory.Call(uintptr(process.handle), at, addressPtr, uintptr(size))

	if state == 0 {
		panic(fmt.Sprintf("Epicly failed: WPM at %x is SUS!", at))
	}
}

//	dll initializer
func (process *Process) getDll(name string) *Dll {
	obj := Dll{name: name}

	base, size := process.getModule(name)

	if base == nil || size == 0 {
		panic(fmt.Sprintf("Epicly failed: Module %s is SUS!", name))
	}

	obj.base = base
	obj.size = size

	fmt.Printf("Grabbed module: %s | base: %x | size: %x\n", obj.name, obj.base, obj.size)

	return &obj
}

//	memory utilities
func dereference(ptr unsafe.Pointer) unsafe.Pointer {
	return unsafe.Pointer(*(*uintptr)(ptr))
}

//	@TODO: implement pattern scanner once vsc doesn't delete random characters anymore
