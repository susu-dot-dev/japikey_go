package main

import (
	"context"
	"fmt"
	"os"

	"github.com/urfave/cli/v3"
)

func main() {
	app := &cli.Command{
		Name:  "jwx",
		Usage: "JWK verification and generation tool",
		Commands: []*cli.Command{
			{
				Name:   "parse",
				Usage:  "Parse JWK JSON from stdin and output public key as base64",
				Action: parseAction,
			},
			{
				Name:      "generate",
				Usage:     "Generate JWKS JSON from base64 public key and UUID",
				ArgsUsage: "[KEY_ID]",
				Action:    generateAction,
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
