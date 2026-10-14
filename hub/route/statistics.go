package route

import (
	"strconv"
	"time"

	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/tunnel/statistic"

	"github.com/metacubex/chi"
	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
	"golang.org/x/exp/slices"
)

func statisticsRouter() http.Handler {
	r := chi.NewRouter()
	r.Get("/", getStatistics)
	r.Delete("/", resetStatistics)
	r.Get("/{dimension}", getStatisticsDimension)
	return r
}

type statisticsQuery struct {
	sort  string
	limit int
}

func parseStatisticsQuery(r *http.Request, defaultLimit int) (statisticsQuery, bool) {
	q := statisticsQuery{sort: r.URL.Query().Get("sort"), limit: defaultLimit}
	switch q.sort {
	case "":
		q.sort = "total"
	case "total", "upload", "download", "connections":
	default:
		return q, false
	}
	if s := r.URL.Query().Get("limit"); s != "" {
		limit, err := strconv.Atoi(s)
		if err != nil || limit < 0 {
			return q, false
		}
		q.limit = limit
	}
	return q, true
}

// getStatistics returns the top entries of every dimension.
func getStatistics(w http.ResponseWriter, r *http.Request) {
	q, ok := parseStatisticsQuery(r, 10)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	state := statistic.DefaultManager.HistoryState()
	resp := render.M{"since": state.Since.Format(time.RFC3339)}
	for _, d := range statistic.Dimensions {
		resp[d] = state.Top(d, q.sort, q.limit)
	}
	render.JSON(w, r, resp)
}

func getStatisticsDimension(w http.ResponseWriter, r *http.Request) {
	dimension := chi.URLParam(r, "dimension")
	if !slices.Contains(statistic.Dimensions, dimension) {
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, ErrNotFound)
		return
	}
	q, ok := parseStatisticsQuery(r, 50)
	if !ok {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, ErrBadRequest)
		return
	}
	state := statistic.DefaultManager.HistoryState()
	render.JSON(w, r, render.M{
		"since":   state.Since.Format(time.RFC3339),
		"entries": state.Top(dimension, q.sort, q.limit),
	})
}

func resetStatistics(w http.ResponseWriter, r *http.Request) {
	statistic.DefaultManager.History().Reset()
	executor.SaveStatistics()
	render.NoContent(w, r)
}
