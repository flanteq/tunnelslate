package server

import (
	"net/http"
	"os"
)

// loginBootstrap reveals only whether the initial-password hint is relevant.
// The password file is never opened or returned to an unauthenticated visitor.
func (s *Server) loginBootstrap(w http.ResponseWriter, r *http.Request) {
	info, err := os.Lstat(s.store.InitialPasswordPath())
	if err != nil && !os.IsNotExist(err) {
		internalError(w, "initial password file status", err)
		return
	}
	available := err == nil && info.Mode().IsRegular()
	jsonResponse(w, http.StatusOK, map[string]bool{"initial_password_available": available})
}
