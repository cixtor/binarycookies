package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/cixtor/binarycookies"
)

var filename string

func main() {
	flag.Usage = func() {
		fmt.Println("Usage: binarycookies [/path/to/Cookies.binarycookies]")
		flag.PrintDefaults()
	}

	flag.Parse()

	if filename = flag.Arg(0); filename == "" {
		flag.Usage()
		return
	}

	file, err := os.Open(filename)

	if err != nil {
		fmt.Println("os.Open", err)
		return
	}

	cook := binarycookies.New(file)

	pages, err := cook.Decode()

	if err != nil {
		fmt.Println(err)
		return
	}

	for _, page := range pages {
		for _, cookie := range page.Cookies {
			fmt.Printf(
				"%s %s %s %s %s",
				cookie.Expires.Format(`2006-01-02 15:04:05`),
				cookie.Domain,
				cookie.Path,
				cookie.Name,
				cookie.Value,
			)

			if cookie.Secure {
				fmt.Printf(" Secure")
			}

			if cookie.HttpOnly {
				fmt.Printf(" HttpOnly")
			}

			if len(cookie.Comment) > 0 {
				fmt.Printf("/* %s */", cookie.Comment)
			}

			fmt.Println()
		}
	}
}
