package cifs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

type ClientStats struct {
	Targets uint64
}

func NewClientStats() (*ClientStats, error) {
	f, err := os.Open("cifs/stats_example.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseClientStats(f)
}

func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Share (unique mount targets):") {
			_, err := fmt.Sscanf(line, "Share (unique mount targets): %d", &stats.Targets)
			if err != nil {
				return nil, err
			}
		}
	}
	return stats, nil
}
