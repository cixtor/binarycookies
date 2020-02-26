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
	}
}
