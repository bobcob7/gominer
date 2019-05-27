package cave

import (
	"fmt"
	"os"

	"github.com/bobcob7/gominer/pe"
)

type Cave struct {
	fileOffset int
	size       int
}

type MetaCaves struct {
	Cave
	pe.Section
}

func (m MetaCaves) Print() string {
	start := m.fileOffset
	if start < int(m.VirtualAddress) {
		start = int(m.VirtualAddress)
	}
	end := m.fileOffset + m.size
	if end > int(m.VirtualAddress+m.VirtualSize) {
		end = int(m.VirtualAddress + m.VirtualSize)
	}
	return fmt.Sprintf(
		`Section Name:	%s
Size:			%d
Address:		0x%08X - 0x%08X
`,
		m.Name,
		m.size,
		start,
		end,
	)
}

func FindCaves(fileName string, threshold int) ([]Cave, error) {
	output := make([]Cave, 0, 10)

	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	buffer := make([]byte, 1)
	var position int
	var caveStart int
	var caveSize int
	var isCave bool
	for {
		_, err := f.Read(buffer)
		if err != nil {
			break
		}
		if buffer[0] == 0x00 {
			if isCave {
				caveSize++
			} else {
				caveStart = position
				isCave = true
			}
		} else {
			if caveSize >= threshold {
				output = append(output, Cave{caveStart, caveSize})
			}
			caveSize = 0
			isCave = false
		}
		position++
	}

	return output, err
}

func Analyse(caves []Cave, sections []pe.Section) []MetaCaves {
	output := make([]MetaCaves, 0)
	for _, cave := range caves {
		start := cave.fileOffset
		end := cave.fileOffset + cave.size
		fmt.Printf("Cave 0x%X-0x%X\n", start, end)
		for startSectionIndex, section := range sections {
			var endSectionIndex int
			sectionStart := int(section.VirtualAddress)
			sectionEnd := sectionStart + int(section.VirtualSize)
			if sectionStart <= start && start >= sectionEnd {
				// starts in section
				for endSectionIndex = startSectionIndex; endSectionIndex < len(sections); endSectionIndex++ {
					section = sections[endSectionIndex]
					sectionStart := int(section.VirtualAddress)
					sectionEnd := sectionStart + int(section.VirtualSize)
					if sectionStart <= end && end >= sectionEnd {
						// ends in section
						break
					}
				}
			}

			// Create caves
			for i := startSectionIndex; i <= endSectionIndex; i++ {
				partMeta := MetaCaves{
					cave,
					sections[i],
				}
				output = append(output, partMeta)
			}
		}
	}
	return output
}
