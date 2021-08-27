package gogo

import (
	"fmt"
	"unsafe"
)

type Context struct {
	csgo      *Process
	client    *Dll
	playerPtr unsafe.Pointer
}

func (context *Context) getPlayer() *Player {
	return *(**Player)(context.playerPtr)
}

func MakeContext() *Context {
	var obj Context

	obj.csgo = getProcess("csgo.exe")
	obj.client = obj.csgo.getDll("client.dll")

	obj.playerPtr = obj.csgo.readMemory(4, uintptr(dereference(obj.csgo.patternScan(obj.client, []byte("\x83\x3D\xCC\xCC\xCC\xCC\xCC\x75\x68\x8B\x0D\xCC\xCC\xCC\xCC\x8B\x01"), 2))))

	return &obj
}

func (context *Context) Run() {
	fmt.Printf("player: %d\n", context.getPlayer().getHealth())
	for {
		//	do something:TM:
	}
}
