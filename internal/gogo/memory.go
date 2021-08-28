package gogo

//	The following is done with inspiration from:
//	https://github.com/jamesmoriarty/gomem/blob/master/internal/kernel32/kernel32.go

import (
	"fmt"
	"unsafe"
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
	handle, _, _ := gCreateToolhelp32Snapshot.Call(kTh32csSnapAll, 0)

	processEntry := ProcessEntry32{entrySize: 304}

	for state, _, _ := gProcess32First.Call(handle, uintptr(unsafe.Pointer(&processEntry))); state != 0; state, _, _ = gProcess32Next.Call(handle, uintptr(unsafe.Pointer(&processEntry))) {
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
		return nil
	}

	handle, _, _ := gOpenProcess.Call(kProcessAllAccess, 0, uintptr(obj.pid))

	if handle == 0 {
		panic(fmt.Sprintf("Epicly failed: Failed grabbing handle of process %s with PID %x (IMPOSTOR!)", obj.name, obj.pid))
		return nil
	}

	obj.handle = handle

	modulesSnap, _, _ := gCreateToolhelp32Snapshot.Call(kTh32csSnapModule|kTh32csSnapModule32, uintptr(obj.pid))

	if handle == 0 {
		panic(fmt.Sprintf("Epicly failed: Failed grabbing modules snapshot of process %s with PID %x (IMPOSTOR!)", obj.name, obj.pid))
		return nil
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

	for state, _, _ := gModule32First.Call(process.modulesSnap, uintptr(unsafe.Pointer(&moduleEntry))); state != 0; state, _, _ = gModule32Next.Call(process.modulesSnap, uintptr(unsafe.Pointer(&moduleEntry))) {
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

	state, _, _ := gReadProcessMemory.Call(process.handle, at, uintptr(addressPtr), uintptr(size), 0)

	if state == 0 {
		panic(fmt.Sprintf("Epicly failed: RPM at %x is SUS!", at))
		return nil
	}

	return addressPtr
}

func (process *Process) readMemoryDll(dll *Dll, size uint32, ptrdiff uintptr) unsafe.Pointer {
	return process.readMemory(size, uintptr(unsafe.Pointer(dll.base))+ptrdiff)
}

func (process *Process) writeMemory(into unsafe.Pointer, size uint32, at uintptr) {
	state, _, _ := gWriteProcessMemory.Call(process.handle, at, uintptr(into), uintptr(size))

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
		return nil
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

func (process *Process) patternScan(dll *Dll, sig []byte, pad int) unsafe.Pointer {
	arrayLength := len(sig)
	scanLength := int(dll.size) - arrayLength

	//	skip first and last page
	for i := kPageSize; i < scanLength-kPageSize; i += kPageSize {
		//	read whole page
		current := process.readMemoryDll(dll, kPageSize, uintptr(i))

		//	page is unreadable, don't care
		if current == nil {
			continue
		}

		//	buffer
		buffer := *(*[kPageSize]byte)(current)

		//	run over every byte
		for j := 0; j < kPageSize-arrayLength; j++ {
			found := true
			for k := 0; k < arrayLength; k++ {
				opcode := buffer[j+k]
				if opcode != sig[k] && sig[k] != 0xCC {
					found = false
					break
				}
			}

			if found {
				//	Unless we do this, the process will literally fail
				fmt.Printf("Found signature at base+%x\n", i+j+pad)

				result := process.readMemoryDll(dll, 4, uintptr(i+j+pad))

				//	result should be readable (and valid)
				if result == nil {
					continue
				}

				return result
			}
		}
	}

	return nil
}
