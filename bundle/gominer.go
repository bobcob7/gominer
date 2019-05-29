package main

import (
	"encoding/base64"
	"fmt"

	"syscall/js"
	"strings"

	"github.com/bobcob7/gominer/bundle/cave"
	"github.com/bobcob7/gominer/bundle/cave/pe"
)

var reader js.Value
var sizeSliderValue js.Value
var minCaveSize int
var currentFileName string
var currentFileBuffer []byte
var currentFileMeta pe.PE

func main() {
	done := make(chan bool, 1)
	doc := js.Global().Get("document")
	
	newReader := js.Global().Get("FileReader")
	reader = newReader.New()
	fmt.Println(reader)

	minCaveSize = 300
	currentFileName = "test"

	title := doc.Call("getElementById", "title")
	upload := doc.Call("getElementById", "upload")
	sizeSlider := doc.Call("getElementById", "sizeSlider")
	sizeSliderValue = doc.Call("getElementById", "sizeSliderValue")
	fmt.Sscan(sizeSlider.Get("value").String(), &minCaveSize)

	uploadCallback := js.FuncOf(hello)
	sliderCallback := js.FuncOf(sliderChange)
	sliderCommitCallback := js.FuncOf(sliderCommit)
	uploadedCallback := js.FuncOf(uploaded)
	errorUploadCallback := js.FuncOf(uploadError)
	uploadAbortedCallback := js.FuncOf(uploadAborted)
	defer uploadCallback.Release()
	defer sliderCallback.Release()
	defer sliderCommitCallback.Release()
	defer uploadedCallback.Release()
	defer errorUploadCallback.Release()
	defer uploadAbortedCallback.Release()
	reader.Call("addEventListener", "load", uploadedCallback)
	reader.Call("addEventListener", "error", errorUploadCallback)
	reader.Call("addEventListener", "abort", uploadAbortedCallback)
	upload.Call("addEventListener", "change", uploadCallback)
	sizeSlider.Call("addEventListener", "input", sliderCallback)
	sizeSlider.Call("addEventListener", "change", sliderCommitCallback)
	fmt.Println("Hello Wasm")
	title.Set("innerHTML", "Hello Wasm")
	<-done
}

func uploaded(this js.Value, args []js.Value) interface{} {
	fmt.Println("Finished uploading")
	result := args[0].Get("target").Get("result").String()
	searchString := "base64,"
	index := strings.Index(result, searchString)
	if index < 0 {
		fmt.Println("Error opening file")
		return nil
	}
	sBuffer := result[index+len(searchString):]
	buffer, err := base64.StdEncoding.DecodeString(sBuffer)
	if err != nil {
		fmt.Println("Error decoding file", err)
		return nil
	}
	currentFileMeta, err = pe.NewPE(currentFileName, buffer)
	if err != nil {
		panic(err)
	}
	currentFileBuffer = buffer
	return process(this, args)
}

func process(this js.Value, args []js.Value) interface{} {
	fmt.Println(currentFileMeta.Print())
	caves := cave.FindCaves(currentFileBuffer, minCaveSize)
	coolCaves := cave.Analyse(caves, currentFileMeta.Sections)
	for _, cave := range coolCaves {
		if cave.Characteristics.ExecutableCode {
			fmt.Println(cave.Print())
		}
	}

	return nil
}

func uploadError(this js.Value, args []js.Value) interface{} {
	fmt.Println("Error uploading")
	return nil
}

func uploadAborted(this js.Value, args []js.Value) interface{} {
	fmt.Println("Aborted uploading")
	return nil
}

func hello(this js.Value, args []js.Value) interface{} {
	files := this.Get("files")
	file := files.Index(0)
	currentFileName = file.Get("name").String()
	reader.Call("readAsDataURL", file)
	return nil
}

func sliderChange(this js.Value, args []js.Value) interface{} {
	sSize := this.Get("value").String()
	fmt.Sscan(sSize, &minCaveSize)
	sizeSliderValue.Set("value", sSize)
	return nil
}

func sliderCommit(this js.Value, args []js.Value) interface{} {
	if len(currentFileBuffer) > 0 {
		return process(this, args)
	}
	return nil
}