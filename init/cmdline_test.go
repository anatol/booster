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

	tests := []test{
		// \param00=test00 // an odd case, but we will allow it
		{"\\param00=test00", "param00", "test00", 15},
		// param01=test01
		{"param01=test01", "param01", "test01", 14},
		// "param02=test02"
		{"\"param02=test02\"", "param02", "test02", 16},
		// param03="test03"
		{"param03=\"test03\"", "param03", "test03", 16},
		// '   param04=test04   '
		{"   param04=test04   ", "param04", "test04", 18},
		// param05=te\0st05
		{"param05=te\000st05", "param05", "te", 11},
		// [tab]param06=test06[tab]
		{"\tparam06=test06\t", "param06", "test06", 16},
		// param07=te"st07
		{"param07=te\"st07", "param07", "te\"st07", 15},
		// par"am08=test08
		{"par\"am08=test08", "par\"am08", "test08", 15},
		// param09=test09=test10
		{"param09=test09=test10", "param09", "test09=test10", 21},
		// param10=\"test11=test12\"
		{"param10=\"test11=test12\"", "param10", "test11=test12", 23},
		// param11
		{"param11", "param11", "", 7},
		// "param12"
		{"\"param12\"", "param12", "", 9},
		// param13=
		{"param13=", "param13", "", 8},
		// param14=te\ st14
		{"param14=te\\ st14", "param14", "te st14", 16},
		// param15="te\"st15"
		{"param15=\"te\\\"st15\"", "param15", "te\"st15", 18},
		// param16=te"st16
		{"param16=te\"st16", "param16", "te\"st16", 15},
		// param17="te"st17"
		{"param17=\"te\"st17\"", "param17", "te", 12},
		// param18"=test18
		{"param18\"=test18", "param18\"", "test18", 15},
		// param19=te\nst19
		{"param19=te\nst19", "param19", "te", 11},
		// param20=test20\r
		{"param20=test20\r", "param20", "test20", 15},
		// =test21 // This is a worst case bad junk input, it will return empty key
		{"=test21", "", "test21", 7},
		// param22="test22 param23="test23" // This is a worst case bad junk input, it will mangle 22 and swallow 23
		{"param22=\"test22 param23=\"test23\"", "param22", "test22 param23=", 25},
		// param24="test24 param25=test25 // This is a worst case bad junk input, it will mangle 24 and swallow 25
		{"param24=\"test24 param25=test25", "param24", "test24 param25=test25", 30},
	}

	for _, test := range tests {
		var k, v string
		var i int

		t.Log("Testing ", test.input, "\n")
		k, v, i = getNextParam(test.input, 0)
		require.Equal(t, test.outKey, k)
		require.Equal(t, test.outValue, v)
		require.Equal(t, test.outIndex, i)
	}
}

func TestGetNextParamMulti(t *testing.T) {
	type testOutput struct {
		outKey   string
		outValue string
		outIndex int
	}

	type multiTest struct {
		input  string
		output []testOutput
	}

	tests := []multiTest{
		{
			"rd.luks.uuid=\"639b8fdd-36ba-443e-be3e-e5b335935502\" root=UUID=\"7bbf9363-eb42-4476-8c1c-9f1f4d091385\"",
			[]testOutput{
				{"rd.luks.uuid", "639b8fdd-36ba-443e-be3e-e5b335935502", 51},
				{"root", "UUID=7bbf9363-eb42-4476-8c1c-9f1f4d091385", 100},
			},
		},
	}

	for _, test := range tests {
		var k, v string
		i := 0

		t.Log("Testing ", test.input)
		for _, output := range test.output {
			k, v, i = getNextParam(test.input, i)
			require.Equal(t, output.outKey, k)
			require.Equal(t, output.outValue, v)
			require.Equal(t, output.outIndex, i)
		}
	}
}
