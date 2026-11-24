package route

import (
	"github.com/metacubex/mihomo/component/process"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

// getProcessLookup serves a snapshot of process lookup through the pinned
// BPF maps, or a body reporting it unsupported on builds without the Linux
// reader.
func getProcessLookup(w http.ResponseWriter, r *http.Request) {
	render.JSON(w, r, process.LookupHealth())
}
