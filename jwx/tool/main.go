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
				Usage:  "Parse an RSA or P-256 JWK from stdin and output the public key as base64",
				Action: parseAction,
			},
			{
				Name:      "generate",
				Usage:     "Generate JWKS JSON from base64 public key and UUID",
				ArgsUsage: "[KEY_ID]",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "alg",
						Value: "auto",
						Usage: "key algorithm: ES256 (P-256 point, version 2), RS256 (RSA modulus, version 1) or auto to detect it from the key",
					},
				},
				Action: generateAction,
			},
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
