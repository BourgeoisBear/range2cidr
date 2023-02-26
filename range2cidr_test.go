package range2cidr

import (
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"testing"
)

type r2cc struct {
	Title    string
	IPLo     string
	IPHi     string
	Expected []string
}

var CASES []r2cc = []r2cc{
	r2cc{
		Title: "ARIN",
		IPLo:  "23.128.1.0",
		IPHi:  "23.128.7.255",
		Expected: []string{
			"23.128.1.0/24",
			"23.128.2.0/23",
			"23.128.4.0/22",
		},
	},
	r2cc{
		Title: "Multiple Blocks",
		IPLo:  "61.32.0.0",
		IPHi:  "61.43.255.255",
		Expected: []string{
			"61.40.0.0/14",
			"61.32.0.0/13",
		},
	},
	r2cc{
		Title: "Swapped Ranges",
		IPLo:  "61.32.0.0",
		IPHi:  "61.43.255.255",
		Expected: []string{
			"61.40.0.0/14",
			"61.32.0.0/13",
		},
	},
	r2cc{
		Title: "Empty /32",
		IPLo:  "0.0.0.0",
		IPHi:  "0.0.0.0",
		Expected: []string{
			"0.0.0.0/32",
		},
	},
	r2cc{
		Title: "Ordinary /31",
		IPLo:  "61.32.0.0",
		IPHi:  "61.32.0.1",
		Expected: []string{
			"61.32.0.0/31",
		},
	},
	r2cc{
		Title: "Tiny Multiples - A",
		IPLo:  "0.0.0.254",
		IPHi:  "0.0.1.0",
		Expected: []string{
			"0.0.1.0/32",
			"0.0.0.254/31",
		},
	},
	r2cc{
		Title: "Tiny Multiples - B",
		IPLo:  "0.0.0.1",
		IPHi:  "0.0.0.2",
		Expected: []string{
			"0.0.0.1/32",
			"0.0.0.2/32",
		},
	},
	r2cc{
		Title: "Big IPv4",
		IPLo:  "0.0.0.1",
		IPHi:  "255.255.255.254",
		Expected: []string{
			"0.0.0.1/32",
			"0.0.0.2/31",
			"0.0.0.4/30",
			"0.0.0.8/29",
			"0.0.0.16/28",
			"0.0.0.32/27",
			"0.0.0.64/26",
			"0.0.0.128/25",
			"0.0.1.0/24",
			"0.0.2.0/23",
			"0.0.4.0/22",
			"0.0.8.0/21",
			"0.0.16.0/20",
			"0.0.32.0/19",
			"0.0.64.0/18",
			"0.0.128.0/17",
			"0.1.0.0/16",
			"0.2.0.0/15",
			"0.4.0.0/14",
			"0.8.0.0/13",
			"0.16.0.0/12",
			"0.32.0.0/11",
			"0.64.0.0/10",
			"0.128.0.0/9",
			"1.0.0.0/8",
			"2.0.0.0/7",
			"4.0.0.0/6",
			"8.0.0.0/5",
			"16.0.0.0/4",
			"32.0.0.0/3",
			"64.0.0.0/2",
			"128.0.0.0/2",
			"192.0.0.0/3",
			"224.0.0.0/4",
			"240.0.0.0/5",
			"248.0.0.0/6",
			"252.0.0.0/7",
			"254.0.0.0/8",
			"255.0.0.0/9",
			"255.128.0.0/10",
			"255.192.0.0/11",
			"255.224.0.0/12",
			"255.240.0.0/13",
			"255.248.0.0/14",
			"255.252.0.0/15",
			"255.254.0.0/16",
			"255.255.0.0/17",
			"255.255.128.0/18",
			"255.255.192.0/19",
			"255.255.224.0/20",
			"255.255.240.0/21",
			"255.255.248.0/22",
			"255.255.252.0/23",
			"255.255.254.0/24",
			"255.255.255.0/25",
			"255.255.255.128/26",
			"255.255.255.192/27",
			"255.255.255.224/28",
			"255.255.255.240/29",
			"255.255.255.248/30",
			"255.255.255.252/31",
			"255.255.255.254/32",
		},
	},
}

// TODO: more test cases (ipv6, odd endpoints, etc)

func expandExpected(t *testing.T, vals []string) []netip.Prefix {

	var err error
	RET := make([]netip.Prefix, len(vals))

	for ix := range vals {
		RET[ix], err = netip.ParsePrefix(vals[ix])
		if err != nil {
			t.Fatal(err)
		}
	}

	// base address, ascending
	sort.Slice(RET, func(i, j int) bool {
		return RET[i].Addr().Less(RET[j].Addr())
	})

	return RET
}

func TestDeaggregate(t *testing.T) {

	for _, C := range CASES {

		fmt.Print(C.Title + ", " + C.IPLo + " - " + C.IPHi + ": ")

		LO, E := netip.ParseAddr(C.IPLo)
		if E != nil {
			t.Fatal(E)
		}

		HI, E := netip.ParseAddr(C.IPHi)
		if E != nil {
			t.Fatal(E)
		}

		RET, E := Deaggregate(LO, HI)
		if E != nil {
			t.Fatal(E)
		}

		EXP := expandExpected(t, C.Expected)

		if reflect.DeepEqual(RET, EXP) {

			for ix := range RET {
				fmt.Printf("\t%s\n", RET[ix].String())
			}
			fmt.Println(cmsg(true, "SUCCESS!"))

		} else {

			t.Log(cmsg(false, "MISMATCH!"))

			le, lr := len(EXP), len(RET)
			max := le
			if lr > max {
				max = lr
			}

			const SZ_FMT = "%40s %40s\n"
			t.Logf(SZ_FMT, "EXPECTED", "RETURNED")
			for i := 0; i < max; i++ {

				var sE, sR string

				if i < le {
					sE = EXP[i].String()
				}

				if i < lr {
					sR = RET[i].String()
				}

				t.Logf(SZ_FMT, sE, sR)
			}
			t.FailNow()
		}
	}
}

func TestV4Conv(t *testing.T) {

	s := []string{
		"127.0.0.1",
		"192.168.1.0",
		"0.0.0.0",
		"255.255.255.255",
	}

	ip := make([]netip.Addr, len(s))

	for ix := range s {
		ip[ix] = netip.MustParseAddr(s[ix])
	}

	fmt.Println("IPv4 Conversions")
	for _, val := range ip {

		n, ok := V4ToUint32(val)
		val2 := Uint32ToV4(n)
		fmt.Println("\t", val.String(), n, ok, val2.String())

		if !ok {
			t.Log(cmsg(false, "V4ToUint32 Failure"))
			t.FailNow()
		}

		if val != val2 {
			t.Log(cmsg(false, "V4To/FromUint32 Mismatch"))
			t.FailNow()
		}
	}
	fmt.Println(cmsg(true, "SUCCESS!"))
}

func TestV6Conv(t *testing.T) {

	s := []string{
		"2606:cb00::",
		"2620:0:c70::",
		"2620:12b:8000::",
	}

	ip := make([]netip.Addr, len(s))

	for ix := range s {
		ip[ix] = netip.MustParseAddr(s[ix])
	}

	fmt.Println("IPv6 Conversions")
	for _, val := range ip {

		n := V6ToBig(val)
		val2 := BigToV6(n)
		fmt.Println("\t", val.String(), n, val2.String())

		if val != val2 {
			t.Log(cmsg(false, "V6To/FromBig Mismatch"))
			t.FailNow()
		}
	}
	fmt.Println(cmsg(true, "SUCCESS!"))
}

func cmsg(bOk bool, v string) string {
	var pfx string
	if bOk {
		pfx = "\x1b[92m"
	} else {
		pfx = "\x1b[91m"
	}
	return pfx + v + "\x1b[0m"
}
