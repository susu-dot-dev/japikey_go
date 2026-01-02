package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "jwx",
		Usage: "JWK verification and generation tool",
		Commands: []*cli.Command{
			{
				Name:    "parse",
				Usage:   "Parse JWK JSON from stdin and output public key as base64",
				Action:  parseAction,
			},
			{
				Name:      "generate",
				Usage:     "Generate JWKS JSON from base64 public key and UUID",
				Args:      true,
				ArgsUsage: "[KEY_ID]",
				Action:    generateAction,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}