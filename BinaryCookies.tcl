section "Header" {
	big_endian
	requires 0 "63 6f 6f 6b"
	bytes 4 "Signature"

	set size [uint32 "Size"]

	for {set pageOffset 0} {$pageOffset < $size} {incr pageOffset} {
		uint32 "Page Offset #$pageOffset"
	}
}
