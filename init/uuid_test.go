package main

import (
	"testing"
)

func TestParseUUIDFromRoot(t *testing.T) {
	testCases := []struct {
		name string

		cmdroot      string
		expectedUUID string
	}{
		{
			name:         "quoted uuid",
			cmdroot:      "UUID=\"0d7b09a9-8928-4451-8037-21f7a329fed8\"",
			expectedUUID: "0d7b09a9-8928-4451-8037-21f7a329fed8",
		},
		{
			name:         "non-quoted uuid",
			cmdroot:      "UUID=\"0d7b09a9-8928-4451-8037-21f7a329fed8\"",
			expectedUUID: "0d7b09a9-8928-4451-8037-21f7a329fed8",
		},
		{
			name:         "malformed uuid",
			cmdroot:      "UUID=\"0d7b09a9-8928-4451-8037-21f7a329fed\"",
			expectedUUID: "",
		},
		{
			name:         "extra quoted uuid",
			cmdroot:      "UUID=\"\"0d7b09a9-8928-4451-8037-21f7a329fed8\"\"",
			expectedUUID: "",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, uuidParseTest(testCase.cmdroot, testCase.expectedUUID))
	}
}

func uuidParseTest(cmdroot, expectedUUID string) func(t *testing.T) {
	return func(t *testing.T) {
		uuid := parseUUIDFromCmdRoot(cmdroot)
		if uuid != expectedUUID {
			t.Fatalf("expected uuid to be %s, but saw %s", expectedUUID, uuid)
		}
	}
}
