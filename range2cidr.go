// Package range2cidr deaggregates an IP address range into a list of network prefixes (CIDR blocks).

package range2cidr

import (
	"bytes"
	"encoding/binary"
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
func splitIntoCidrs(bsIpLo, bsIpHi []byte) (RET []netip.Prefix) {

	NI := big.NewInt

	bigLo := NI(0).SetBytes(bsIpLo)
	bigHi := NI(0).SetBytes(bsIpHi)
	nBytes := len(bsIpLo)
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

		// convert calculated base addr back into a netip.Addr,
		// re-using low address slice as an intermediary
		bigLo.FillBytes(bsIpLo)
		addr, ok := netip.AddrFromSlice(bsIpLo)
		if ok {
			prfx := netip.PrefixFrom(addr, nBits-nStep)
			RET = append(RET, prfx)
		}

		bigLo.Add(bigLo, NI(0).Lsh(NI(1), uint(nStep)))
	}

	return
}

func V4ToUint32(ipaddr netip.Addr) (uint32, bool) {
	if ipaddr.Is4In6() {
		ipaddr = ipaddr.Unmap()
	}
	if !ipaddr.Is4() {
		return 0, false
	}
	bsV4 := ipaddr.As4()
	return binary.BigEndian.Uint32(bsV4[:]), true
}

func Uint32ToV4(n32 uint32) netip.Addr {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], n32)
	return netip.AddrFrom4(tmp)
}

func ToBig(addr netip.Addr) *big.Int {
	var v big.Int
	if addr.Is4() {
		bs := addr.As4()
		return v.SetBytes(bs[:])
	} else if addr.Is6() {
		bs := addr.As16()
		return v.SetBytes(bs[:])
	} else {
		return nil
	}
}

func BigToV6(nBig *big.Int) netip.Addr {
	if nBig == nil {
		return netip.Addr{}
	}
	var tmp [16]byte
	nBig.FillBytes(tmp[:])
	return netip.AddrFrom16(tmp)
}

func BigToV4(nBig *big.Int) netip.Addr {
	if nBig == nil {
		return netip.Addr{}
	}
	var tmp [4]byte
	nBig.FillBytes(tmp[:])
	return netip.AddrFrom4(tmp)
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
