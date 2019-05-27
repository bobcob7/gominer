package main

import (
	"fmt"

	"github.com/bobcob7/gominer/cave"
	"github.com/bobcob7/gominer/pe"
)

func main() {
	fileName := "putty.exe"
	meta, err := pe.NewPE(fileName)
	if err != nil {
		panic(err)
	}
	caves, err := cave.FindCaves(fileName, 300)
	fmt.Printf("%s\n", meta.Print())

	coolCaves := cave.Analyse(caves, meta.Sections)
	for _, cave := range coolCaves {
		if cave.Characteristics.ExecutableCode {
			fmt.Println(cave.Print())
		}
	}
}
