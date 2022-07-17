package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseParamsInvalidLuksOptions(t *testing.T) {
	luksMappings = nil

	require.Error(t, parseParams("rd.luks.name=ab6d7d78-b816-4495-928d-766d6607035e=root rd.luks.name=7843d77f-cdd6-4289-a4de-a708c4aacede=swap rd.luks.name=7f28c723-fd6b-4640-bc94-9366edd8880d=cache root=UUID=e8e81fc3-8f81-4a3a-ac3d-aab36aa0c45f video=efifb:on add_efi_memmap zswap.enabled=1 zswap.max_pool_percent=100 zswap.zpool=z3fold resume=/dev/mapper/swap acpi=copy_dsdt rd.luks.options=tpm2-device=auto"))
}

func TestParseParams(t *testing.T) {
	luksMappings = nil

	require.NoError(t, parseParams("rd.luks.name=ab6d7d78-b816-4495-928d-766d6607035e=root rd.luks.name=7843d77f-cdd6-4289-a4de-a708c4aacede=swap rd.luks.name=7f28c723-fd6b-4640-bc94-9366edd8880d=cache root=UUID=e8e81fc3-8f81-4a3a-ac3d-aab36aa0c45f video=efifb:on add_efi_memmap rd.luks.options=no-read-workqueue zswap.enabled=1 zswap.max_pool_percent=100 zswap.zpool=z3fold resume=/dev/mapper/swap acpi=copy_dsdt"))
	require.Equal(t, "/dev/mapper/swap", cmdResume.data)
	require.Equal(t, refPath, cmdResume.format)
	require.Equal(t, "e8e81fc3-8f81-4a3a-ac3d-aab36aa0c45f", cmdRoot.data.(UUID).toString())
	require.Equal(t, refFsUUID, cmdRoot.format)
	require.Len(t, luksMappings, 3)

	root := luksMappings[0]
	require.Equal(t, "root", root.name)
	require.Equal(t, []string{"no-read-workqueue"}, root.options)
	require.Equal(t, refFsUUID, root.ref.format)
	require.Equal(t, "ab6d7d78-b816-4495-928d-766d6607035e", root.ref.data.(UUID).toString())

	swap := luksMappings[1]
	require.Equal(t, "swap", swap.name)
	require.Equal(t, []string{"no-read-workqueue"}, swap.options)
	require.Equal(t, refFsUUID, swap.ref.format)
	require.Equal(t, "7843d77f-cdd6-4289-a4de-a708c4aacede", swap.ref.data.(UUID).toString())

	cache := luksMappings[2]
	require.Equal(t, "cache", cache.name)
	require.Equal(t, []string{"no-read-workqueue"}, cache.options)
	require.Equal(t, refFsUUID, cache.ref.format)
	require.Equal(t, "7f28c723-fd6b-4640-bc94-9366edd8880d", cache.ref.data.(UUID).toString())
}

func TestGetNextParam(t *testing.T) {
	type test struct {
		input    string
		outKey   string
		outValue string
		outIndex int
	}

	var tests = []test{
		// param01=test0
		test{"param01=test0", "param01", "test0", 13},
		// "param02=test0"
		test{"\"param02=test0\"", "param02", "test0", 15},
		// param03="test0"
		test{"param03=\"test0\"", "param03", "test0", 15},
		// '   param04=test0   '
		test{"   param04=test0   ", "param04", "test0", 17},
		// param05=te\0st
		test{"param05=te\000st0", "param05", "te", 11},
		// [tab]param06=test0[tab]
		test{"\tparam06=test0\t", "param06", "test0", 15},
		// param07=te"st0
		test{"param07=te\"st0", "param07", "te\"st0", 14},
		// par"am08=test0
		test{"par\"am08=test0", "par\"am08", "test0", 14},
		// param09=test1=test2
		test{"param09=test1=test2", "param09", "test1=test2", 19},
		// param10=\"test1=test2\"
		test{"param10=\"test1=test2\"", "param10", "test1=test2", 21},
		// param11
		test{"param11", "param11", "", 7},
		// "param12"
		test{"\"param12\"", "param12", "", 9},
		// param13=
		test{"param13=", "param13", "", 8},
		// param14=te\ st0
		test{"param14=te\\ st0", "param14", "te st0", 15},
		// param15="te\"st0"
		test{"param15=\"te\\\"st0\"", "param15", "te\"st0", 17},
		// param16=te"st0
		test{"param16=te\"st0", "param16", "te\"st0", 14},
		// param17="te"st0"
		test{"param17=\"te\"st0\"", "param17", "te", 12},
		// param18"=test0
		test{"param18\"=test0", "param18\"", "test0", 14},
		// param19=te\nst0
		test{"param19=te\nst0", "param19", "te", 11},
		// param20=test0\r
		test{"param20=test0\r", "param20", "test0", 14},
		// =test0 // This is a worst case bad junk input, it will return empty key
		test{"=test0", "", "test0", 6},
		// param21="test0 param22="test1" // This is a worst case bad junk input, it will mangle 21 and swallow 22
		test{"param21=\"test0 param22=\"test1\"", "param21", "test0 param22=", 24},
		// param23="test0 param24=test1 // This is a worst case bad junk input, it will mangle 23 and swallow 24
		test{"param23=\"test0 param24=test1", "param23", "test0 param24=test1", 28},
	}

	for _, test := range tests {
		var k, v string
		var i int

		k, v, i = getNextParam(test.input, 0)
		require.Equal(t, test.outKey, k)
		require.Equal(t, test.outValue, v)
		require.Equal(t, test.outIndex, i)
	}

}
