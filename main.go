package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/jeffallen/opvault"
	"golang.org/x/crypto/ssh/terminal"
)

var fn = flag.String("file", os.ExpandEnv("$HOME/Dropbox/1Password/1Password.opvault"), "Filename of the vault")
var prof = flag.String("profile", "default", "Profile")
var profs = flag.Bool("profiles", false, "Dump all profiles.")
var hideTrashed = flag.Bool("hideTrashed", true, "Hide trashed items.")

func main() {
	flag.Parse()

	vault, err := opvault.Open(*fn)
	if err != nil {
		log.Fatal("Directory ", *fn, ":", err)
	}

	if *profs {
		pn, err := vault.ProfileNames()
		if err != nil {
			log.Fatal("Could not get profile names:", err)
		}
		for _, x := range pn {
			fmt.Println(x)
		}
		return
	}

	p, err := vault.Profile(*prof)
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
				if item.Trashed() && *hideTrashed {
					continue
				}

				if item.Trashed() {
					fmt.Fprintf(term, "Title: %v (trashed)\n", item.Title())
				} else {
					fmt.Fprintf(term, "Title: %v\n", item.Title())
				}

				fmt.Fprintf(term, "Category: %v\n", item.Category())

				d, err := item.Detail()
				if err != nil {
					fmt.Fprintf(term, "error: %v", err)
				}

				if d.Password() != "" {
					fmt.Fprintf(term, "password -> %v\n", d.Password())
				}

				for _, f := range d.Fields() {
					fmt.Fprintf(term, "%v -> %v\n", f.Name(), f.Value())
				}
			}
		}
		fmt.Fprintln(term)
	}
}
