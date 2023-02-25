# range2cidr
De-aggregates an IP address range into a list of network prefixes (CIDR blocks)

[![GoDoc](https://godoc.org/github.com/BourgeoisBear/range2cidr?status.png)](http://godoc.org/github.com/BourgeoisBear/range2cidr)

Returns a list of prefixes (CIDR blocks) that covers the given IP range.

For example, if:

	ipLo = 23.128.1.0
	ipHi = 23.128.7.255

then Deaggregate(ipLo, ipHi) will return:

	23.128.1.0/24
	23.128.2.0/23
	23.128.4.0/22
