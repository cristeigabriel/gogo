package main

import (
	"github.com/cristeigabriel/gogo/internal/gogo"
)

func main() {
	gogo.Instance = gogo.MakeContext()
	gogo.Instance.Run()
}
