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
	return (*Player)(dereference(context.playerPtr))
}

func MakeContext() *Context {
	var obj Context

	obj.csgo = getProcess("csgo.exe")
	obj.client = obj.csgo.getDll("client.dll")

	obj.playerPtr = obj.csgo.readMemoryDll(obj.client, 4, 0xD8A2DC)

	return &obj
}

func (context *Context) Run() {
	fmt.Printf("player: %d\n", context.getPlayer().getHealth())
	for {
		//	do something:TM:
	}
}
