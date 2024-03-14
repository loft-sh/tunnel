package handlers

import (
	"encoding/json"
	"net/http"
)

type APIError struct {
	Error  string `json:"error"`
	Reason string `json:"reason"`
}

func handleAPIError(w http.ResponseWriter, err error, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	err = json.NewEncoder(w).Encode(APIError{
		Error:  err.Error(),
		Reason: reason,
	})
	if err != nil {
		_, _ = w.Write([]byte(err.Error()))
	}
}
