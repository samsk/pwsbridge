package main

import (
	"fmt"
	"os"

	"github.com/samsk/pwsbridge/internal/app"
)

func main() {
	if err := app.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "pwsbridge: %v\n", err)
		os.Exit(1)
	}
}
