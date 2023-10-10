package handlers

import (
	"encoding/json"
	"log"
	"net/http"
)

type APIError struct {
	Error  error  `json:"error"`
	Reason string `json:"reason"`
}

func handleAPIError(w http.ResponseWriter, err error, reason string) {
	log.Printf("API error: %s - %v", reason, err)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	err = json.NewEncoder(w).Encode(APIError{
		Error:  err,
		Reason: reason,
	})
	if err != nil {
		_, _ = w.Write([]byte(err.Error()))
	}
}
