package oneme

import (
	"crypto/rand"
	"fmt"

	"github.com/leon03131/fork-openflux/utils"
)

// logInfo is debug-only: routine call signaling chatter may contain
// participant ids and ICE candidates (IPs), which must not leak into
// default logs (AGENTS.md rule 4).
func logInfo(format string, args ...interface{}) {
	utils.Debugf("[INF] "+format, args...)
}

func logError(format string, args ...interface{}) {
	fmt.Printf("[ERR] "+format+"\n", args...)
}

func genUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
