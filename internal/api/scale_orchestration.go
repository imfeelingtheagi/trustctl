package api

import (
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/perf"
)

func (a *API) getScaleOrchestration(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusOK, perf.ScaleOrchestration(time.Now().UTC().Format(time.RFC3339)))
}
