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
	"time"

	"github.com/chzyer/readline"
	"github.com/creachadair/otp/otpauth"
	"github.com/jeffallen/opvault"
	"github.com/pcarrier/gauth/gauth"
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

	var pwBytes []byte
	envPass := os.Getenv("PASS")
	if envPass != "" {
		pwBytes = []byte(envPass)
	}
	if pwBytes == nil {
		fmt.Fprint(rl, "password? ")
		bpw, err := readline.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Print("password read: ", err)
			return
		}
		pwBytes = bpw
	}

	err = p.Unlock(string(pwBytes))
	for i := range pwBytes {
		pwBytes[i] = 0
	}
	if err != nil {
		log.Print("unlock: ", err)
		return
	}
	for {
		lookup := os.Getenv("lookup")
		once := true
		var err error
		if lookup == "" {
			lookup, err = rl.Readline()
			once = false
		}
		if err != nil {
			if err != io.EOF {
				fmt.Printf("error: %v\n", err)
			}
			return
		}

		lookup = strings.ToLower(lookup)
		fmt.Printf("looking up %q\n", lookup)

		cnt := 0
		items, _ := p.Items()
		for _, item := range items {
			if lookup == "*" || strings.Contains(strings.ToLower(item.Title()), lookup) {
				if item.Trashed() && *hideTrashed {
					continue
				}

				detail, err := item.Detail()
				if err != nil {
					fmt.Printf("could not get detail: %v\n", err)
				}
				otp := ""
				for _, section := range detail.Sections() {
					for _, field := range section.Fields() {
						if strings.HasPrefix(field.Value(), "otpauth://") {
							otp = field.Value()
						}
					}
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

				// only try to do OTP on the first one
				if cnt == 0 {
					url, err := otpauth.ParseURL(otp)
					if err == nil {
						_, cur, next, err := gauth.Codes(url)
						if err == nil {
							fmt.Println("OTP code 1: ", cur)
							time.Sleep(time.Duration(gauth.DefaultPeriod) * time.Second)
							fmt.Println("OTP code 2: ", next)
						} else {
							fmt.Printf("error: %v", err)
						}
					} else {
						fmt.Printf("error: %v", err)
					}
				}

				cnt++
			}
		}
		if once {
			return
		}
	}
}
