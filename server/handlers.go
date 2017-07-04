package server

import (
	"net/http"
)

// HealthCheckHandler a http handler return 200 OK when server health is fine.
func (s *Server) HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}
