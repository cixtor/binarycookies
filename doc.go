// Package binarycookies implements an encoder and decoder to create and read
// binary cookies respectively.
//
// In computing, a magic cookie, or just cookie for short, is a token or short
// packet of data passed between communicating programs, where the data is
// typically not meaningful to the recipient program. The contents are opaque
// and not usually interpreted until the recipient passes the cookie data back
// to the sender or perhaps another program at a later time. The cookie is
// often used like a ticket – to identify a particular event or transaction.
//
// An HTTP cookie is a small piece of data sent from a website and stored on
// the user's computer by the user's web browser while the user is browsing.
// Cookies were designed to be a reliable mechanism for websites to remember
// stateful information or to record the user's browsing activity. They can
// also be used to remember arbitrary pieces of information that the user
// previously entered into form fields such as names, addresses, passwords,
// and credit-card numbers.
//
// References:
//
// - https://en.wikipedia.org/wiki/Magic_cookie
// - https://en.wikipedia.org/wiki/HTTP_cookie
// - https://tools.ietf.org/html/rfc2109
// - https://tools.ietf.org/html/rfc2965
// - https://tools.ietf.org/html/rfc6265
package binarycookies
