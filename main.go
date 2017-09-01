package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/miquella/opvault"
)

var fn = flag.String("file", os.ExpandEnv("$HOME/Dropbox/1Password/1Password.opvault"), "Filename of the vault")

func main() {
	flag.Parse()

	vault, err := opvault.Open(*fn)
	if err != nil {
		log.Fatal("Directory ", *fn, ":", err)
	}

	p, err := vault.Profile("default")
	if err != nil {
		log.Fatal("profile lookup", err)
	}

	state, _ := terminal.MakeRaw(int(os.Stdin.Fd()))
	defer func() {
		terminal.Restore(int(os.Stdin.Fd()), state)
		os.Stdin.Write([]byte("\n"))
	}()

	term := terminal.NewTerminal(os.Stdin, "lookup? ")

	var pw string
	pw = os.Getenv("PASS")
	if pw == "" {
		pw, err = term.ReadPassword("password? ")
		if err != nil {
			log.Print("password read: ", err)
			return
		}
	}

	err = p.Unlock(pw)
	if err != nil {
		log.Print("unlock: ", err)
		return
	}

	for {
		lookup, err := term.ReadLine()
		if err != nil {
			if err != io.EOF {
				term.Write([]byte(fmt.Sprintf("error: %v\n", err)))
			}
			return
		}

		lookup = strings.ToLower(lookup)

		items, err := p.Items()
		for _, item := range items {
			if lookup == "*" || strings.Contains(strings.ToLower(item.Title()), lookup) {
				fmt.Fprintf(term, "\nTitle: %v\n", item.Title())

				d, err := item.Detail()
				if err != nil {
					term.Write([]byte(fmt.Sprintf("error: %v\n", err)))
				}

				for _, f := range d.Fields() {
					term.Write([]byte(fmt.Sprintf("%v -> %v\n", f.Name(), f.Value())))
				}
			}
		}
	}
}
