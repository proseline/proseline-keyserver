package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "path: %s", r.URL.Path[1:])
}

func main() {
	http.HandleFunc("/", handler)
	portString := os.Getenv("PORT")
	if portString == "" {
		portString = "8080"
	}
	log.Fatal(http.ListenAndServe(":"+portString, nil))
}
