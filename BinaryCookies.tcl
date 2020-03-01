section "Header" {
	big_endian
	requires 0 "63 6f 6f 6b"
	bytes 4 "Signature"

	set size [uint32 "Size"]

	for {set pageOffset 0} {$pageOffset < $size} {incr pageOffset} {
		uint32 "Page Offset #$pageOffset"
	}
}

for {set pageIndex 0} {$pageIndex < $size} {incr pageIndex} {
	section "Page #$pageIndex" {
		little_endian
		bytes 4 "Page Tag"
		set numCookies [uint32 "Num. Cookies"]
		for {set i 1} {$i <= $numCookies} {incr i} {
			uint32 "Cookie Offset #$i"
		}
		bytes 4 "Page End"

		for {set cookieIndex 0} {$cookieIndex < $numCookies} {incr cookieIndex} {
			section "Cookie #$cookieIndex" {
				little_endian
				set cookieSize [uint32 "Cookie Size"]
				bytes 4 "Unknown"
				uint32 "Cookie Flags"
				bytes 4 "Unknown"
				set domainOffset [uint32 "Domain Offset"]
				set nameOffset [uint32 "Name Offset"]
				set pathOffset [uint32 "Path Offset"]
				set valueOffset [uint32 "Value Offset"]
				set commentOffset [uint32 "Comment Offset"]
				bytes 4 "End Header"
				big_endian
				double "Expiration Time"
				double "Creation Time"
				if {$commentOffset > 0} {
					ascii [expr {$domainOffset - $commentOffset}] "Comment"
				}
				ascii [expr {$nameOffset - $domainOffset}] "Domain"
				ascii [expr {$pathOffset - $nameOffset}] "Name"
				ascii [expr {$valueOffset - $pathOffset}] "Path"
				ascii [expr {$cookieSize - $valueOffset}] "Value"
			}
		}
	}
}

section "Footer" {
	bytes 8 "Checksum"

	# Additional bytes are part of an optional bplist dictionary that usually
	# contains a dictionary with a key NSHTTPCookieAcceptPolicy and a value
	# representing the cookie accept policy for all tasks within sessions based
	# on this configuration.
	#
	# Example:
	#
	# $ hexdump -v -C Cookies.binarycookies | tail -n5
	# 00000000  62 70 6c 69 73 74 30 30  d1 01 02 5f 10 18 4e 53  |bplist00..._..NS|
	# 00000010  48 54 54 50 43 6f 6f 6b  69 65 41 63 63 65 70 74  |HTTPCookieAccept|
	# 00000020  50 6f 6c 69 63 79 10 02  08 0b 26 00 00 00 00 00  |Policy....&.....|
	# 00000030  00 01 01 00 00 00 00 00  00 00 03 00 00 00 00 00  |................|
	# 00000040  00 00 00 00 00 00 00 00  00 00 28                 |..........(|
	# 0000004b
	#
	# $ plutil -p Tail.plist
	# {
	#   "NSHTTPCookieAcceptPolicy" => 2
	# }
	if ![end] {
		big_endian
		set bplistSize [uint32 "bplist size"]
		bytes $bplistSize "bplist content"
	}
}
