# Binary Cookies [![GoReport](https://goreportcard.com/badge/github.com/cixtor/binarycookies)](https://goreportcard.com/report/github.com/cixtor/binarycookies) [![GoDoc](https://godoc.org/github.com/cixtor/binarycookies?status.svg)](https://godoc.org/github.com/cixtor/binarycookies)

Go (golang) implementation of an encoder and decoder for the Binary Cookies file format used by Safari and other applications based on WebKit to store HTTP cookies. A CLI program is also included to allow you to inspect and manipulate the binary cookies from the commodity of your Terminal.

<img src="screenshot.png" align="center">

## Usage

If you are going to use this Go module in your project:

```sh
go get github.com/cixtor/binarycookies
```

If you want to install the command line interface (CLI):

```sh
go get github.com/cixtor/binarycookies/cmd/binarycookies
```

## Example

The majority of macOS applications store their web cookies in `~/Library/Cookies/` while others _—using containers—_ do so in `~/Library/Containers/<APP_ID>/Data/Library/Cookies/`. We can use simple Unix commands to find all these files and dump their content using the CLI, like so:

```sh
find ~/Library/Cookies/ -name "*.binarycookies" -exec binarycookies {} \;
```
