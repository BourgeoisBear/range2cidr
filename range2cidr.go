/*
Aggregate() merges a list of IP ranges into a minimal set of covering ranges.

Deaggregate() breaks a single IP range into a list of covering network prefixes.

A number of address helper functions are exposed for convenience.

This library usually operates on addresses as [16]byte values, as returned by netip.Addr.As16().

To convert a netip.Addr into [16]byte:

	addr.As16()

To unmap an address back into IPv4 format:

	if addr.Is4In6() {
		return addr.Unmap()
	}
*/
package range2cidr

import (
	"encoding/binary"
	"math/big"
	"net/netip"
	"slices"
)

// de-aggregate a range of IP addresses into a list of covering network prefixes.
func (v Range) Deaggregate() []netip.Prefix {
	// sort range
	v.Normalize()
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

// aggregate (merge) adjacent and contained ranges.
//
// NOTE: mutates sR.
func Aggregate(sR []Range) []Range {

	if len(sR) < 2 {
		return sR
	}

	for i := range sR {
		sR[i].Normalize()
	}

	// .A asc
	slices.SortFunc(sR, func(a, b Range) int {
		return Cmp(&a.A, &b.A)
	})

	var one [16]byte
	SetBit(&one, 0, true)
	j := 0
	for i := 1; i < len(sR); i += 1 {

		/*
			sub-range
			0123456789
			A    Z
			 X Y

			intersection
			0123456789
			A    Z
			  X    Y

			adjacent
			0123456789
			A   Z
			     X  Y

			X in [A,Z+1]: ret [A, max(Y,Z)]
		*/

		// sub-range & intersection
		cmpAA := Cmp(&sR[i].A, &sR[j].A)
		nextZ, _ := Add(&sR[j].Z, &one)
		cmpAZ := Cmp(&sR[i].A, &nextZ)

		// X in [A,Z]
		if (cmpAA >= 0) && (cmpAZ <= 0) {
			// max(Y,Z)
			if Cmp(&sR[i].Z, &sR[j].Z) > 0 {
				sR[j].Z = sR[i].Z
			}
			continue
		}

		// otherwise append to stack, unchanged
		j += 1
		sR[j] = sR[i]
	}

	return sR[:j+1]
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

// get n-th bit in a.  returns true if set, false if not.
func GetBit(a *[16]byte, n uint) bool {
	byteIx := 15 - int(n>>3)
	if byteIx < 0 {
		return false
	}
	return (a[byteIx] & (1 << (n & 0b111))) != 0
}

// set/clear n-th bit in a.
func SetBit(a *[16]byte, n uint, bSet bool) {
	byteIx := 15 - int(n>>3)
	if byteIx < 0 {
		return
	}
	if bSet {
		a[byteIx] |= 1 << (n & 0b111)
	} else {
		a[byteIx] &^= 1 << (n & 0b111)
	}
}

type Range struct {
	A, Z [16]byte
}

// sort range to ensure that A <= Z.
func (v *Range) Normalize() {
	if Cmp(&v.A, &v.Z) > 0 {
		C := v.Z
		v.Z = v.A
		v.A = C
	}
}

// convert first, last addresses to a Range struct
func RangeFromAddrs(first, last netip.Addr) Range {
	var ret Range
	ret.A = first.As16()
	ret.Z = last.As16()
	ret.Normalize()
	return ret
}

// convert network prefix to a Range struct
func RangeFromPrefix(pfx netip.Prefix) Range {
	var ret Range
	ret.A = pfx.Masked().Addr().As16()
	ret.Z = ret.A
	ixEnd := (pfx.Addr().BitLen() - pfx.Bits())
	for i := 0; i < ixEnd; i += 1 {
		SetBit(&ret.Z, uint(i), true)
	}
	return ret
}
