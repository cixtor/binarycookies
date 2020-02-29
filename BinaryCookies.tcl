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
}
