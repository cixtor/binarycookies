package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"

	"github.com/cixtor/binarycookies"
)

var filename string
var netscape bool
var filter string

func main() {
	flag.Usage = func() {
		fmt.Println("Usage: binarycookies [-netscape] [-filter regexp] [/path/to/Cookies.binarycookies]")
		flag.PrintDefaults()
	}

	flag.BoolVar(&netscape, "netscape", false, "use the Netscape cookie format")
	flag.StringVar(&filter, "filter", "", "filter results by regexp on domain")

	flag.Parse()

	if filename = flag.Arg(0); filename == "" {
		flag.Usage()
		return
	}

	var re *regexp.Regexp
	if len(filter) > 0 {
		var err error
		if re, err = regexp.Compile(filter); err != nil {
			fmt.Println("regexp.Compile", err)
			return
		}
	}

	file, err := os.Open(filename)

	if err != nil {
		fmt.Println("os.Open", err)
		return
	}

	defer file.Close()

	cook := binarycookies.New(file)

	pages, err := cook.Decode()

	if err != nil {
		fmt.Println(err)
		return
	}

	if netscape {
		fmt.Println("# Netscape HTTP Cookie File")
	}

	for _, page := range pages {
		for _, cookie := range page.Cookies {
			if re != nil && !re.Match(cookie.Domain) {
				continue
			}

			if netscape {
				fmt.Printf(
					"%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
					cookie.Domain,
					boolField(cookie.Flags&0x40 == 0),
					cookie.Path,
					boolField(cookie.Flags&4 != 0),
					cookie.Expires.Unix(),
					cookie.Name,
					cookie.Value,
				)
				continue
			}

			fmt.Println(cookie.String())
		}
	}
}

func boolField(b bool) string {
	if b {
		return "TRUE"
	}
	return "FALSE"
}
