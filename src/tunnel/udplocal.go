package tunnel

import (
	"net"

	"github.com/metacubex/mihomo/log"
)

// closeLocalConns closes the TPROXY local conns recorded for a key. Both a
// session's reply loop and a replacement whose dial failed can be the last to
// hold the entry, and each must close its local conns or leak the write-back
// sockets with their reader goroutines. A session replaced by another
// sender's is not the entry's holder anymore, so its teardown leaves them.
func closeLocalConns(key string) func(string, *net.UDPConn) bool {
	return func(rAddr string, conn *net.UDPConn) bool {
		conn.Close()
		log.Debugln("Closing TProxy local conn... lAddr=%s rAddr=%s", key, rAddr)
		return true
	}
}
