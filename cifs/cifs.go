package cifs

import (
	"bufio"
	"fmt"
	"io"
	"os"
)

type ClientStats struct {
	Header   Header
	SMB1List []*SMB1
	SMB2List []*SMB2
}

type SMB1 struct {
	Server      string
	Share       string
	SMB         uint64
	OpLocks     uint64
	Reads       uint64
	ReadsBytes  uint64
	Writes      uint64
	WritesBytes uint64
	Flushes     uint64
	Locks       uint64
	Hardlinks   uint64
	Symlinks    uint64
	Opens       uint64
	Closes      uint64
	Deletes     uint64
	PosixOpens  uint64
	PosixMkdirs uint64
	Mkdirs      uint64
	Rmdirs      uint64
	Renames     uint64
	T2Renames   uint64
	FindFirst   uint64
	FNext       uint64
	FClose      uint64
}

type SMB2 struct {
	Server                 string
	Share                  string
	SMB                    uint64
	NegotiatesSent         uint64
	NegotiatesFailed       uint64
	SessionSetupsSent      uint64
	SessionSetupsFailed    uint64
	LogoffsSent            uint64
	LogoffsFailed          uint64
	TreeConnectsSent       uint64
	TreeConnectsFailed     uint64
	TreeDisconnectsSent    uint64
	TreedisconnectsFailed  uint64
	CreatesSent            uint64
	CreatesFailed          uint64
	ClosesSent             uint64
	ClosesFailed           uint64
	FlushesSent            uint64
	FlushesFailed          uint64
	ReadsSent              uint64
	ReadsFailed            uint64
	WritesSent             uint64
	WritesFailed           uint64
	LocksSent              uint64
	LocksFailed            uint64
	IOCTLsSent             uint64
	IOCTLsFailed           uint64
	CancelsSent            uint64
	CancelsFailed          uint64
	EchosSent              uint64
	EchosFailed            uint64
	QueryDirectoriesSent   uint64
	QueryDirectoriesFailed uint64
	ChangeNotifiesSent     uint64
	ChangeNotifiesFailed   uint64
	QueryInfosSent         uint64
	QueryInfosFailed       uint64
	SetInfosSent           uint64
	SetInfosFailed         uint64
	OpLockBreaksSent       uint64
	OpLockBreaksFailed     uint64
}

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

func NewClientStats() (*ClientStats, error) {
	f, err := os.Open("cifs/stats_example.txt")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ParseClientStats(f)
}

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
	// parse SMB blocks
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Println(line)
	}
	return stats, nil
}
