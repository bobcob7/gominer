package pe

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
)

// COFFHeader is a standard Common Object File Format. Size 24
type COFFHeader struct {
	Signature            [4]byte
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbolTable  uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// StandardCOFFFields is the first set of fields in the optional PE header. Size 28
type StandardCOFFFields struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
	BaseOfData              uint32
}

// StandardCOFFFieldsPlus is the first set of fields in the optional PE32+ header. Size 28
type StandardCOFFFieldsPlus struct {
	Magic                   uint16
	MajorLinkerVersion      uint8
	MinorLinkerVersion      uint8
	SizeOfCode              uint32
	SizeOfInitializedData   uint32
	SizeOfUninitializedData uint32
	AddressOfEntryPoint     uint32
	BaseOfCode              uint32
}

// WindowsSpecificFields is the second set of fields in the optional PE header. Size 62
type WindowsSpecificFields struct {
	ImageBase                   uint32
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint32
	SizeOfStackCommit           uint32
	SizeOfHeapReserve           uint32
	SizeOfHeapCommit            uint32
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

// WindowsSpecificFieldsPlus is the second set of fields in the optional PE32+ header. Size 82
type WindowsSpecificFieldsPlus struct {
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
}

// DataDirectories is the third set of fields in the optional PE header. Size 128
type DataDirectories struct {
	ExportTable           uint64
	ImportTable           uint64
	ResourceTable         uint64
	ExceptionTable        uint64
	CertificateTable      uint64
	BaseRelocationTable   uint64
	Debug                 uint64
	ArchitectureData      uint64
	GlobalPtr             uint64
	TLSTable              uint64
	LoadConfigTable       uint64
	BoundImport           uint64
	ImportAddressTable    uint64
	DelayImportDescriptor uint64
	CLRRuntimeHeader      uint64
	_                     uint64
}

// OptionalHeaderPlus is an optional header of a PE32+ file. Size 230.
type OptionalHeaderPlus struct {
	StandardCOFFFieldsPlus
	WindowsSpecificFieldsPlus
	DataDirectories
}

// OptionalHeader is an optional header of a PE32 file. Size 230.
type OptionalHeader struct {
	StandardCOFFFields
	WindowsSpecificFields
	DataDirectories
}

type RealSection struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

type PE struct {
	filename            string
	AddressOfEntryPoint uint32
	BaseOfCode          uint32
	SizeOfStackReserve  uint64
	SizeOfStackCommit   uint64
	SizeOfHeapReserve   uint64
	SizeOfHeapCommit    uint64
	Sections            []Section
}

func NewPE(fileName string) (output PE, err error) {
	// Open file
	f, err := os.Open(fileName)
	if err != nil {
		return
	}
	output.filename = fileName

	// Read offset in DOS stub at 0x3C
	var offset uint32
	buffer := make([]byte, 4)
	n, err := f.ReadAt(buffer, 0x3c)
	if err != nil {
		return
	}
	if n != 4 {
		err = errors.New("Could not read offset")
		return
	}
	buf := bytes.NewReader(buffer)
	binary.Read(buf, binary.LittleEndian, &offset)

	// Read COFF Header
	var coffHeader COFFHeader
	buffer = make([]byte, 24)
	n, err = f.ReadAt(buffer, int64(offset))
	if err != nil {
		return
	}
	if n != 24 {
		err = errors.New("Could not read offset")
		return
	}
	buf = bytes.NewReader(buffer)
	binary.Read(buf, binary.LittleEndian, &coffHeader)

	// Read Optional Header
	headerSize := int(coffHeader.SizeOfOptionalHeader)
	if headerSize > 0 {
		buffer = make([]byte, headerSize)
		n, err = f.ReadAt(buffer, int64(offset+24))
		if err != nil {
			return
		}
		if n != headerSize {
			err = errors.New("Could not read offset")
			return
		}

		if buffer[0] != 0xb {
			err = errors.New("Only supports PE32/PE32+ files")
			return
		}
		isPlus := false
		if buffer[1] == 2 {
			isPlus = true
		} else if buffer[1] != 1 {
			err = errors.New("Only supports PE32/PE32+ files")
			return
		}
		if isPlus {
			optionalHeader := OptionalHeaderPlus{}
			buf = bytes.NewReader(buffer)
			err = binary.Read(buf, binary.LittleEndian, &optionalHeader)
			if err != nil {
				return
			}
			output.AddressOfEntryPoint = optionalHeader.AddressOfEntryPoint
			output.BaseOfCode = optionalHeader.BaseOfCode
			output.SizeOfHeapCommit = optionalHeader.SizeOfHeapCommit
			output.SizeOfHeapReserve = optionalHeader.SizeOfHeapReserve
			output.SizeOfStackCommit = optionalHeader.SizeOfStackCommit
			output.SizeOfStackReserve = optionalHeader.SizeOfStackReserve
		} else {
			optionalHeader := OptionalHeader{}
			buf = bytes.NewReader(buffer)
			err = binary.Read(buf, binary.LittleEndian, &optionalHeader)
			if err != nil {
				return
			}
			output.AddressOfEntryPoint = optionalHeader.AddressOfEntryPoint
			output.BaseOfCode = optionalHeader.BaseOfCode
			output.SizeOfHeapCommit = uint64(optionalHeader.SizeOfHeapCommit)
			output.SizeOfHeapReserve = uint64(optionalHeader.SizeOfHeapReserve)
			output.SizeOfStackCommit = uint64(optionalHeader.SizeOfStackCommit)
			output.SizeOfStackReserve = uint64(optionalHeader.SizeOfStackReserve)
		}
	}

	// Read Sections
	sectionSizes := int(coffHeader.NumberOfSections) * 40
	sectionsOffset := headerSize + int(offset) + 24
	buffer = make([]byte, sectionSizes)
	n, err = f.ReadAt(buffer, int64(sectionsOffset))
	if err != nil {
		return
	}
	if n != sectionSizes {
		err = errors.New("Could not read sections")
		return
	}
	output.Sections = make([]Section, coffHeader.NumberOfSections)
	sectionStart := 0
	tempSection := RealSection{}
	for sectionNum := 0; sectionNum < int(coffHeader.NumberOfSections); sectionNum++ {
		buf = bytes.NewReader(buffer[sectionStart : sectionStart+40])
		sectionStart += 40
		err = binary.Read(buf, binary.LittleEndian, &tempSection)
		output.Sections[sectionNum] = newSection(tempSection)
		if err != nil {
			fmt.Printf("Could not read section#%d: %#v\n", sectionNum, err)
			return
		}
	}
	return
}

func (p PE) Print() string {
	output := fmt.Sprintf(`File:			%s
Entrypoint address:	0x%08X
Base of code:		0x%08X
`,
		p.filename,
		p.AddressOfEntryPoint,
		p.BaseOfCode,
	)

	for i, section := range p.Sections {
		output += fmt.Sprintf("Section #%d\n", i+1)
		output += section.Print()
	}
	return output
}
