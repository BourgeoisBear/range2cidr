// Package range2cidr deaggregates an IP address range into a list of network prefixes (CIDR blocks).

package range2cidr

import (
	"bytes"
	"math/big"
	"net/netip"
)

type RErr int

const (
	EIpVersionMismatch RErr = iota
	EIpInvalid
)

func (e RErr) Error() string {
	switch e {
	case EIpVersionMismatch:
		return "IP version mismatch between HI and LO addresses"
	case EIpInvalid:
		return "invalid address supplied"
	}
	return "unknown error"
}

/*
Returns a list of prefixes (CIDR blocks) that covers the given IP range.

For example, if:

	ipLo = 23.128.1.0
	ipHi = 23.128.7.255

then Deaggregate(ipLo, ipHi) will return:

	23.128.1.0/24
	23.128.2.0/23
	23.128.4.0/22
*/
func Deaggregate(ipLo, ipHi netip.Addr) ([]netip.Prefix, error) {

	// check valid
	if !ipLo.IsValid() && !ipHi.IsValid() {
		return nil, EIpInvalid
	}

	// handle 4in6
	if ipLo.Is4In6() {
		ipLo = ipLo.Unmap()
	}
	if ipHi.Is4In6() {
		ipHi = ipHi.Unmap()
	}

	// check type
	if !(ipLo.Is4() && ipHi.Is4()) && !(ipLo.Is6() && ipHi.Is6()) {
		return nil, EIpVersionMismatch
	}

	// sort starting range
	sLo := ipLo.AsSlice()
	sHi := ipHi.AsSlice()
	if bytes.Compare(sLo, sHi) == 1 {
		C := sHi
		sHi = sLo
		sLo = C
	}

	return splitIntoCidrs(sLo, sHi), nil
}

// Expects ipLo & ipHi to be slices of the same size, where ipLo <= ipHi.
func splitIntoCidrs(ipLo, ipHi []byte) (RET []netip.Prefix) {

	NI := big.NewInt

	bigLo := NI(0).SetBytes(ipLo)
	bigHi := NI(0).SetBytes(ipHi)
	nBytes := len(ipLo)
	nBits := nBytes * 8

	// bigLo <= bigHi
	for bigLo.Cmp(bigHi) != 1 {

		nStep := 0
		lowOrderMask := NI(0)

		for bigLo.Bit(nStep) == 0 {

			// grow mask from low order for each nStep
			lowOrderMask.SetBit(lowOrderMask, nStep, 1)

			// OR mask with bigLo address
			NEXT := NI(0).Set(bigLo)
			NEXT.Or(NEXT, lowOrderMask)

			// stop when next > bigHi
			if NEXT.Cmp(bigHi) == 1 {
				break
			}

			nStep += 1
		}

		// filling because math/big only uses as many bytes as necessary
		// while netip.Addr has expectations
		bsBaseIp := make([]byte, nBytes)

		// TODO: verify that this is endian-safe
		bigLo.FillBytes(bsBaseIp)

		addr, ok := netip.AddrFromSlice(bsBaseIp)
		if ok {
			prfx := netip.PrefixFrom(addr, nBits-nStep)
			RET = append(RET, prfx)
		}

		bigLo.Add(bigLo, NI(0).Lsh(NI(1), uint(nStep)))
	}

	return
}

/*
func printBits(lbl string, iV interface{}) {

	if len(lbl) > 0 {
		fmt.Printf("%10s: ", lbl)
	}

	printByte := func(val []byte) {
		nBytes := len(val)
		for ix, b := range val {
			fmt.Printf("%08b", b)
			if ix != nBytes-1 {
				fmt.Print("|")
			}
		}
	}

	switch val := iV.(type) {

	case net.IPMask:
		printByte(val)

	case net.IP:
		printByte(val)

	case []byte:
		printByte(val)

	case *big.Int:
		printByte(val.Bytes())

	default:
		fmt.Printf("%+v", val)
	}

	fmt.Println("")
}
*/
