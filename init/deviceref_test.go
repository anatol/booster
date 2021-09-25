package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDeviceRef(t *testing.T) {
	check := func(path string, format refFormat, data interface{}) {
		ref, err := parseDeviceRef("test", path, true)
		require.NoError(t, err)

		require.Equal(t, format, ref.format)
		require.Equal(t, data, ref.data)
	}

	check("/dev/foobar", refPath, "/dev/foobar")
	check("UUID=cdda787d-d583-4fb8-a4ec-d242ac61db1c", refFsUUID, UUID{205, 218, 120, 125, 213, 131, 79, 184, 164, 236, 210, 66, 172, 97, 219, 28})
	check("LABEL=hello", refFsLabel, "hello")
	check("LABEL=привет", refFsLabel, "привет")

	check("PARTUUID=cdda787d-d583-4fb8-a4ec-d242ac61db1c", refGptUUID, UUID{205, 218, 120, 125, 213, 131, 79, 184, 164, 236, 210, 66, 172, 97, 219, 28})
	check("PARTLABEL=hello", refGptLabel, "hello")
	check("PARTLABEL=привет", refGptLabel, "привет")
}
