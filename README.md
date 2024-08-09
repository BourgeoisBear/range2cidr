# range2cidr

[![GoDoc](https://img.shields.io/badge/pkg.go.dev-doc-blue)](http://pkg.go.dev/.)

Aggregate() merges a list of IP ranges into a minimal set of covering ranges.

Deaggregate() breaks a single IP range into a list of covering network prefixes.

A number of address helper functions are exposed for convenience.

This library usually operates on addresses as [16]byte values, as returned by netip.Addr.As16().

To convert a netip.Addr into [16]byte:

```go
addr.As16()
```

To unmap an address back into IPv4 format:

```go
if addr.Is4In6() {
	return addr.Unmap()
}
```

The last step is crucial if you want results in v4 format instead of 4in6.
