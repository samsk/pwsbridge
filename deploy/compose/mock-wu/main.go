package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
)

func main() {
	var mu sync.Mutex
	var lastQuery string
	mux := http.NewServeMux()
	mux.HandleFunc("/weatherstation/updateweatherstation.php", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		lastQuery = r.URL.RawQuery
		mu.Unlock()
		log.Printf("host=%s query=%s", r.Host, r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "success\n")
	})
	mux.HandleFunc("/last", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		q := lastQuery
		mu.Unlock()
		fmt.Fprint(w, q)
	})
	addr := ":80"
	if v := os.Getenv("LISTEN"); v != "" {
		addr = v
	}
	log.Fatal(http.ListenAndServe(addr, mux))
}
