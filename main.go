package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/chzyer/readline"
	"github.com/jeffallen/opvault"
)

var home = func() string { u, _ := user.Current(); return u.HomeDir }()
var fn = flag.String("file", filepath.Join(home, "Dropbox", "1Password", "1Password.opvault"), "Filename of the vault.")
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

	rl, err := readline.New("lookup? ")

	var pw string
	pw = os.Getenv("PASS")
	if pw == "" {
		fmt.Fprint(rl, "password? ")
		bpw, err := readline.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Print("password read: ", err)
			return
		}
		pw = string(bpw)
	}

	err = p.Unlock(pw)
	if err != nil {
		log.Print("unlock: ", err)
		return
	}
	for {
		lookup, err := rl.Readline()
		if err != nil {
			if err != io.EOF {
				fmt.Printf("error: %v\n", err)
			}
			return
		}

		lookup = strings.ToLower(lookup)
		fmt.Printf("looking up %q\n", lookup)

		items, _ := p.Items()
		for _, item := range items {
			//println("item:", item.Title())
			if lookup == "*" || strings.Contains(strings.ToLower(item.Title()), lookup) {
				if item.Trashed() && *hideTrashed {
					continue
				}

				if item.Trashed() {
					fmt.Printf("Title: %v (trashed)\n", item.Title())
				} else {
					fmt.Printf("Title: %v\n", item.Title())
				}

				fmt.Printf("Category: %v\n", item.Category())

				d, err := item.Detail()
				if err != nil {
					fmt.Printf("error: %v", err)
				}

				if d.Password() != "" {
					fmt.Printf("password -> %v\n", d.Password())
				}

				for _, f := range d.Fields() {
					fmt.Printf("%v -> %v\n", f.Name(), f.Value())
				}
			}
		}
	}
}
