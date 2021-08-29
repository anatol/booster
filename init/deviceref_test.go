package main

import (
	"reflect"
	"testing"
)

func TestParseDeviceRef(t *testing.T) {
	check := func(path string, format refFormat, data interface{}) {
		ref, err := parseDeviceRef("test", path, true)
		if err != nil {
			t.Fatal(err)
		}

		if ref.format != format {
			t.Fatalf("invalid ref format, expected %d, got %d", format, ref.format)
		}
		if !reflect.DeepEqual(ref.data, data) {
			t.Fatalf("invalid ref format, expected %v, got %v", data, ref.data)
		}
	}

	check("/dev/foobar", refName, "/dev/foobar")
	check("UUID=cdda787d-d583-4fb8-a4ec-d242ac61db1c", refFsUuid, UUID{205, 218, 120, 125, 213, 131, 79, 184, 164, 236, 210, 66, 172, 97, 219, 28})
	check("LABEL=hello", refFsLabel, "hello")
	check("LABEL=привет", refFsLabel, "привет")

	check("PARTUUID=cdda787d-d583-4fb8-a4ec-d242ac61db1c", refGptUuid, UUID{205, 218, 120, 125, 213, 131, 79, 184, 164, 236, 210, 66, 172, 97, 219, 28})
	check("PARTLABEL=hello", refGptLabel, "hello")
	check("PARTLABEL=привет", refGptLabel, "привет")
}
