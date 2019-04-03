package main

import (
	"fmt"

	"github.com/bobcob7/gominer/pe"
)

func main() {
	meta, err := pe.NewPE("putty.exe")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%#v\n", meta)
}
