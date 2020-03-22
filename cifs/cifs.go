package cifs

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
)

// ClientStats describes our CIFS statistics file.
type ClientStats struct {
	Header Header
	Blocks []*Block
}

// Block stores each block with server, share and all metrics.
// Server and share are useful for labeling.
type Block struct {
	Server  string
	Share   string
	Metrics []uint64
}

// Header stores all header information from the CIFS header.
// A []uint64 slice would be maybe a better solution...
// At least as long slices are ordered. We could use the same approach as for the metrics in block.
type Header struct {
	CIFSSession     uint64
	Targets         uint64
	SMBReq          uint64
	SMBBuf          uint64
	SMBSmallReq     uint64
	SMBSmallBuf     uint64
	Op              uint64
	Session         uint64
	ShareReconnects uint64
	MaxOp           uint64
	AtOnce          uint64
}

// This is our multiline regex for the SMB blocks.
// We can possibly get rid of the named regex groups.
var re = regexp.MustCompile(`(?m)(?:(?:(?P<SMBID>\d+)\) \\\\(?P<Server>[A-Za-z1-9-.]+)(?P<Share>.+)\nSMBs:\s+(?P<SMB>\d+) Oplocks breaks:\s+(?P<OpLocks>\d+)\nReads:\s+(?P<Reads>\d+) Bytes:\s+(?P<ReadsBytes>\d+)\nWrites:\s+(?P<Writes>\d+) Bytes:\s+(?P<WritesBytes>\d+)\nFlushes:\s+(?P<Flushes>\d+)\nLocks:\s+(?P<Locks>\d+) HardLinks:\s+(?P<Hardlinks>\d+) Symlinks:\s+(?P<Symlinks>\d+)\nOpens:\s+(?P<Opens>\d+) Closes:\s+(?P<Closes>\d+) Deletes:\s+(?P<Deletes>\d+)\nPosix Opens:\s+(?P<PosixOpens>\d+) Posix Mkdirs:\s+(?P<PosixMkdirs>\d+)\nMkdirs:\s+(?P<Mkdirs>\d+) Rmdirs:\s+(?P<Rmdirs>\d+)\nRenames:\s+(?P<Renames>\d+) T2 Renames\s+(?P<T2Renames>\d+)\nFindFirst:\s+(?P<FindFirst>\d+) FNext\s+(?P<FNext>\d+) FClose\s+(?P<FClose>\d+)|(?P<SMB3ID>\d+)\) \\\\(?P<SMB3Server>[A-Za-z1-9-.]+)(?P<SMB3Share>.+)\nSMBs:\s+(?P<SMB3>\d+)\nNegotiates:\s+(?P<NegotiatesSent>\d+) sent\s+(?P<NegotiatesFailed>\d+) failed\nSessionSetups:\s+(?P<SessionSetupsSent>\d+) sent\s+(?P<SessionSetupsFailed>\d+) failed\nLogoffs:\s+(?P<LogoffsSent>\d+) sent\s+(?P<LogoffsFailed>\d+) failed\nTreeConnects:\s+(?P<TreeConnectsSent>\d+) sent\s+(?P<TreeConnectsFailed>\d+) failed\nTreeDisconnects:\s+(?P<TreeDisconnectsSent>\d+) sent\s+(?P<TreeDisconnectsFailed>\d+) failed\nCreates:\s+(?P<CreatesSent>\d+) sent\s+(?P<CreatesFailed>\d+) failed\nCloses:\s+(?P<ClosesSent>\d+) sent\s+(?P<ClosesFailed>\d+) failed\nFlushes:\s+(?P<FlushesSent>\d+) sent\s+(?P<FlushesFailed>\d+) failed\nReads:\s+(?P<ReadsSent>\d+) sent\s+(?P<ReadsFailed>\d+) failed\nWrites:\s+(?P<WritesSent>\d+) sent\s+(?P<WritesFailed>\d+) failed\nLocks:\s+(?P<LocksSent>\d+) sent\s+(?P<LocksFailed>\d+) failed\nIOCTLs:\s+(?P<IOCTLsSent>\d+) sent\s+(?P<IOCTLsFailed>\d+) failed\nCancels:\s+(?P<CancelsSent>\d+) sent\s+(?P<CancelsFailed>\d+) failed\nEchos:\s+(?P<EchosSent>\d+) sent\s+(?P<EchosFailed>\d+) failed\nQueryDirectories:\s+(?P<QueryDirectoriesSent>\d+) sent\s+(?P<QueryDirectoriesFailed>\d+) failed\nChangeNotifies:\s+(?P<ChangeNotifiesSent>\d+) sent\s+(?P<ChangeNotifiesFailed>\d+) failed\nQueryInfos:\s+(?P<QueryInfosSent>\d+) sent\s+(?P<QueryInfosFailed>\d+) failed\nSetInfos:\s+(?P<SetInfosSent>\d+) sent\s+(?P<SetInfosFailed>\d+) failed\nOplockBreaks:\s+(?P<OpLockBreaksSent>\d+) sent\s+(?P<OpLockBreaksFailed>\d+) failed)+)`)

// NewClientStats opens the cifs stats file and returns our parsed CIFS client statistics.
func NewClientStats() (*ClientStats, error) {
	f, err := os.Open("cifs/stats_example.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseClientStats(f)
}

// parseHeader uses fmt.Sscanf() for matching all information in the header.
// I hope this approach is faster than using a multiline regex for the header.
func (stats *ClientStats) parseHeader(line string) {
	if _, err := fmt.Sscanf(line, "CIFS Session: %d", &stats.Header.CIFSSession); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Share (unique mount targets): %d", &stats.Header.Targets); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "SMB Request/Response Buffer: %d Pool size: %d", &stats.Header.SMBReq, &stats.Header.SMBBuf); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "SMB Small Req/Resp Buffer: %d Pool size: %d", &stats.Header.SMBSmallReq, &stats.Header.SMBSmallBuf); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Operations (MIDs): %d", &stats.Header.Op); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "%d session %d share reconnects", &stats.Header.Session, &stats.Header.ShareReconnects); err == nil {
		return
	}
	if _, err := fmt.Sscanf(line, "Total vfs operations: %d maximum at one time: %d", &stats.Header.MaxOp, &stats.Header.AtOnce); err == nil {
		return
	}
}

// parseSMBBlocks uses a multiline regex for matching all SMB blocks.
// SMB1/2 blocks start at match position 2
// SMB3 blocks start at match position 27
func (stats *ClientStats) parseSMBBlocks(file string) {
	matches := re.FindAllStringSubmatch(file, -1)
	for _, match := range matches {
		// We need to match the right SMB block
		// If match[1] == "" then we have a SMB3 version Block
		if match[1] == "" {
			block := &Block{
				// These are hard offsets right now for the matched SMB3 block
				Server:  match[27],
				Share:   match[28],
				Metrics: []uint64{},
			}
			// match[29] is where the metrics start for the matched SMB3 block
			for i := 29; i < len(match); i++ {
				m, err := strconv.ParseUint(match[i], 10, 64)
				if err != nil {
					break
				}
				block.Metrics = append(block.Metrics, m)
			}
			stats.Blocks = append(stats.Blocks, block)
			// Here we go into a SMB1/2 version Block
		} else {
			block := &Block{
				Server:  match[2],
				Share:   match[3],
				Metrics: []uint64{},
			}
			// match[4] is where the metrics start for the matched SMB1/2 block
			for i := 4; i < len(match); i++ {
				m, err := strconv.ParseUint(match[i], 10, 64)
				if err != nil {
					break
				}
				block.Metrics = append(block.Metrics, m)
			}
			stats.Blocks = append(stats.Blocks, block)
		}
	}
}

// ParseClientstats scans the CIFS statistics file for the header and breaks.
// Then it scans the rest of the file and calls parseSMBBlocks for the multiline regex for
// matching all SMB blocks.
func ParseClientStats(r io.Reader) (*ClientStats, error) {
	stats := &ClientStats{}
	scanner := bufio.NewScanner(r)
	// parse Header
	headerLen := 9
	for scanner.Scan() {
		if headerLen == 0 {
			break
		}
		line := scanner.Text()
		stats.parseHeader(line)
		headerLen--
	}
	// construct SMB block file
	var file string
	for scanner.Scan() {
		line := scanner.Text()
		// We need to add a newline here, otherwise we will end up with one line and our
		// multiline regex will not match.
		file += line + "\n"
	}
	stats.parseSMBBlocks(file)
	return stats, nil
}
