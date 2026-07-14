package main

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestInitConfigEmergencyShellPasswordRoundTrip(t *testing.T) {
	in := InitConfig{EmergencyShellPassword: goldenPHC}
	data, err := yaml.Marshal(&in)
	require.NoError(t, err)
	require.Contains(t, string(data), "emergency_shell_password")

	var out InitConfig
	require.NoError(t, yaml.Unmarshal(data, &out))
	require.Equal(t, goldenPHC, out.EmergencyShellPassword)
}
