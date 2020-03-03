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

## Specification

Binary Cookies are binary files containing several pieces of data that together form an array of objects representing persistent web cookies for different applications in the macOS and iOS application ecosystem. Nowadays, almost every application implements some sort of web view to offer in-app purchases and license validation. All the information transmitted via these web views is stored in these binary files.

**Note:** BE stands for Big-endian and LE stands for Little-endian.

| Variable | Size | Type | Description |
|----------|------|------|-------------|
| signature | 4 | byte | File signature must be equal to `[]byte{0x636f6f6b}` or `String("cook")` |
| numPages | 4 | BE_uint32 | Number of pages in the file |
| pageOffset | 4 | BE_uint32 | Page offset. Repeat this N times where `N = numPages` |
| pageStart | 4 | byte | Marks the beginning of a page. Must be equal to `[]byte{0x00000100}` |
| numCookies | 4 | LE_uint32 | Number of cookies in the page |
| cookieOffset | 4 | LE_uint32 | Cookie offset. Repeat this N times where `N = numCookies` |
| pageEnd | 4 | byte | Marks the end of a page. Must be equal to `[]byte{0x00000000}` |

Immediately after `pageEnd` we can read the page cookies. Repeat the steps below N times where `N = numCookies`.

| Variable | Size | Type | Description |
|----------|------|------|-------------|
| cookieSize | 4 | LE_uint32 | Cookie size. Number of bytes associated to the cookie |
| unknownOne | 4 | byte | Unknown field possibly related to the cookie flags |
| cookieFlags | 4 | LE_uint32 | `0x0:None` - `0x1:Secure` - `0x4:HttpOnly` - `0x5:Secure+HttpOnly` |
| unknownTwo | 4 | byte | Unknown field possibly related to the cookie flags |
| domainOffset | 4 | LE_uint32 | Cookie domain offset |
| nameOffset | 4 | LE_uint32 | Cookie name offset |
| pathOffset | 4 | LE_uint32 | Cookie path offset |
| valueOffset | 4 | LE_uint32 | Cookie value offset |
| commentOffset | 4 | LE_uint32 | Cookie comment offset |
| endHeader | 4 | byte | Marks the end of a header. Must be equal to `[]byte{0x00000000}` |
| expires | 8 | float64 | Cookie expiration time in Mac epoch time. Add 978307200 to turn into Unix |
| creation | 8 | float64 | Cookie creation time in Mac epoch time. Add 978307200 to turn into Unix |
| comment | N | LE_uint32 | Cookie comment string. `N = domainOffset - commentOffset` |
| domain | N | LE_uint32 | Cookie domain string. `N = nameOffset - domainOffset` |
| name | N | LE_uint32 | Cookie name string. `N = pathOffset - nameOffset` |
| path | N | LE_uint32 | Cookie path string. `N = valueOffset - pathOffset` |
| value | N | LE_uint32 | Cookie value string. `N = cookieSize - valueOffset` |

Immediately after the last cookie in the page we can read another page with `pageStart`.

The last cookie of the last page in the file is followed by an 8-bytes checksum.

An optional number of bytes follow the checksum, these are part of a [Binary Property List](https://en.wikipedia.org/wiki/Property_list) that contains a dictionary with additional information like the cookie accept policy for all tasks within sessions based on the software configuration. A `bplist00` file is a completely different file format we need to decode separately. The first 4-bytes after the checksum are the BE_uint32 representing the size of the binary property list. The remaining bytes represent the data we need to decode using a bplist parser.
