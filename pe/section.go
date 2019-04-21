package pe

import "fmt"

func newSection(s RealSection) (output Section) {
	output.Name = string(s.Name[:])
	output.VirtualSize = s.VirtualSize
	output.VirtualAddress = s.VirtualAddress
	output.SizeOfRawData = s.SizeOfRawData
	output.PointerToRawData = s.PointerToRawData
	output.Characteristics = newSectionCharacteristics(s.Characteristics)
	return
}

type Section struct {
	Name             string
	VirtualSize      uint32
	VirtualAddress   uint32
	SizeOfRawData    uint32
	PointerToRawData uint32
	Characteristics  SectionCharacteristics
}

func (s Section) Print() string {
	return fmt.Sprintf(`	Name:			%s
	Virtual Address:	0x%08X - 0x%08X
	Virtual Size:		%d
	Characteristics:	%s
`,
		s.Name,
		s.VirtualAddress,
		s.VirtualAddress+s.VirtualSize,
		s.VirtualSize,
		s.Characteristics.Print())
}

func newSectionCharacteristics(char uint32) (output SectionCharacteristics) {
	output.ExecutableCode = (char&0x00000020 > 0)
	output.InitializedData = (char&0x00000040 > 0)
	output.UninitializedData = (char&0x00000080 > 0)
	output.Discardable = (char&0x02000000 > 0)
	output.UnCachable = (char&0x04000000 > 0)
	output.UnPagable = (char&0x08000000 > 0)
	output.SharedMemory = (char&0x10000000 > 0)
	output.Executable = (char&0x20000000 > 0)
	output.Readable = (char&0x40000000 > 0)
	output.Writable = (char&0x80000000 > 0)
	return
}

type SectionCharacteristics struct {
	ExecutableCode    bool
	InitializedData   bool
	UninitializedData bool
	Discardable       bool
	UnCachable        bool
	UnPagable         bool
	SharedMemory      bool
	Executable        bool
	Readable          bool
	Writable          bool
}

func (c SectionCharacteristics) Print() string {
	output := ""
	if c.ExecutableCode {
		output += "ExecutableCode "
	}
	if c.InitializedData {
		output += "InitializedData "
	}
	if c.UninitializedData {
		output += "UninitializedData "
	}
	if c.Discardable {
		output += "Discardable "
	}
	if c.UnCachable {
		output += "Uncachable "
	}
	if c.UnPagable {
		output += "Unpagable "
	}
	if c.SharedMemory {
		output += "SharedMemory "
	}
	if c.Executable {
		output += "Executable "
	}
	if c.Readable {
		output += "Readable "
	}
	if c.Writable {
		output += "Writable "
	}
	return output
}
