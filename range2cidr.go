// Package range2cidr deaggregates an IP address range into a list of network prefixes (CIDR blocks).

package range2cidr

import (
	"encoding/binary"
	"math/big"
	"net/netip"
	"slices"
)

type RErr int

const (
	EIpInvalid RErr = iota
)

func (e RErr) Error() string {
	switch e {
	case EIpInvalid:
		return "invalid address supplied"
	}
	return "unknown error"
}

/*
deaggregate an IP address range into the list of network prefixes that cover it.

if:

	v.A = 23.128.1.0
	v.Z = 23.128.7.255

then Deaggregate(ipLo, ipHi) will return:

	23.128.1.0/24
	23.128.2.0/23
	23.128.4.0/22
*/
func (v Range) Deaggregate() []netip.Prefix {
	// sort range
	if Cmp(&v.A, &v.Z) > 0 {
		C := v.Z
		v.Z = v.A
		v.A = C
	}
	return splitIntoPrefixes(v.A, v.Z)
}

// Expects ipLo & ipHi to be slices of the same size, where ipLo <= ipHi.
func splitIntoPrefixes(bsIpLo, bsIpHi [16]byte) (RET []netip.Prefix) {

	// bigLo <= bigHi
	for Cmp(&bsIpLo, &bsIpHi) != 1 {

		nStep := uint(0)
		var lowOrderMask [16]byte

		for !GetBit(&bsIpLo, nStep) {

			// grow mask from low order for each nStep
			SetBit(&lowOrderMask, nStep, true)

			// OR mask with bigLo address
			NEXT := bsIpLo
			for i := range NEXT {
				NEXT[i] |= lowOrderMask[i]
			}

			// stop when next > bigHi
			if Cmp(&NEXT, &bsIpHi) == 1 {
				break
			}

			nStep += 1
		}

		// convert calculated base addr back into a netip.Addr,
		// re-using low address slice as an intermediary
		addr := netip.AddrFrom16(bsIpLo)
		nMaskBits := (16 * 8) - int(nStep)
		if addr.Is4In6() {
			addr = addr.Unmap()
			nMaskBits -= 96
		}
		prfx := netip.PrefixFrom(addr, nMaskBits)
		RET = append(RET, prfx)

		var tmp [16]byte
		SetBit(&tmp, nStep, true)
		bsIpLo, _ = Add(&bsIpLo, &tmp)
	}

	return
}

// aggregate adjacent and contained ranges into a minimal list of network prefixes
func Aggregate(sR []Range) []netip.Prefix {

	switch len(sR) {
	case 0:
		return nil
	case 1:
		return sR[0].Deaggregate()
	}

	// .A asc, .Z desc
	slices.SortFunc(sR, func(a, b Range) int {
		ret := Cmp(&a.A, &b.A)
		if ret == 0 {
			ret = Cmp(&b.Z, &a.Z)
		}
		return ret
	})

	var one [16]byte
	SetBit(&one, 0, true)
	j := 0
	for i := 1; i < len(sR); i += 1 {

		// drop fully-contained range
		cmpA := Cmp(&sR[i].A, &sR[j].A)
		if (cmpA >= 0) && (Cmp(&sR[i].Z, &sR[j].Z) <= 0) {
			continue
		}

		// check for adjacency
		if cmpA > 0 {
			nextZ, _ := Add(&sR[j].Z, &one)
			if Cmp(&sR[i].A, &nextZ) == 0 {
				// merge adjacent
				sR[j].Z = sR[i].Z
				continue
			}
		}

		// otherwise append to stack, unchanged
		j += 1
		sR[j] = sR[i]
	}

	// deaggregate ranges
	ret := make([]netip.Prefix, 0, len(sR))
	j += 1
	for i := 0; i < j; i++ {
		sP := sR[i].Deaggregate()
		ret = append(ret, sP...)
	}

	return ret
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

// compare two IPs.
// the result will be 0 if (a == b), -1 if (a < b), and +1 if (a > b).
func Cmp(a, b *[16]byte) int {
	for i := 0; i < 16; i++ {
		d := int(a[i]) - int(b[i])
		if d < 0 {
			return -1
		} else if d > 0 {
			return 1
		}
	}
	return 0
}

// returns sum of a and b, and carry bit.
func Add(a, b *[16]byte) (ret [16]byte, carry int) {
	for i := 15; i >= 0; i-- {
		v := int(a[i]) + int(b[i]) + carry
		if v < 256 {
			ret[i] = byte(v)
			carry = 0
		} else {
			ret[i] = byte(v & 0xFF)
			carry = 1
		}
	}
	return ret, carry
}

// get bitIx-th bit in a.
func GetBit(a *[16]byte, bitIx uint) bool {
	byteIx := 15 - int(bitIx>>3)
	if byteIx < 0 {
		return false
	}
	return (a[byteIx] & (1 << (bitIx & 0b111))) != 0
}

// set/clear bitIx-th bit in a.
func SetBit(a *[16]byte, bitIx uint, bSet bool) {
	byteIx := 15 - int(bitIx>>3)
	if byteIx < 0 {
		return
	}
	if bSet {
		a[byteIx] |= 1 << (bitIx & 0b111)
	} else {
		a[byteIx] &^= 1 << (bitIx & 0b111)
	}
}

type Range struct {
	A, Z [16]byte
}

func RangeFromAddrs(first, last netip.Addr) (ret Range) {
	ret.A = first.As16()
	ret.Z = last.As16()
	return ret
}

// convert network prefix to first/last addrs in network
func RangeFromPrefix(pfx netip.Prefix) (ret Range) {
	ret.A = pfx.Masked().Addr().As16()
	ret.Z = ret.A
	ixEnd := (pfx.Addr().BitLen() - pfx.Bits())
	for i := 0; i < ixEnd; i += 1 {
		SetBit(&ret.Z, uint(i), true)
	}
	return
}
