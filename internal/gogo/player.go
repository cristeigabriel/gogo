package gogo

import (
	"unsafe"
)

type Player struct{}

func (player *Player) get(size uint32, ptrdiff uintptr) unsafe.Pointer {
	return Instance.csgo.readMemory(size, uintptr(unsafe.Pointer(player))+ptrdiff)
}

func (player *Player) getHealth() int {
	return *(*int)(player.get(4, 0x100))
}
