package main

import (
	"errors"
	"fmt"
	"testing"

	libfido2 "github.com/keys-pub/go-libfido2"
	"github.com/stretchr/testify/require"
)

func TestIsFido2WrongDevice(t *testing.T) {
	impl := &fido2Impl{}

	require.True(t, impl.IsFido2WrongDevice(libfido2.ErrNoCredentials))
	require.True(t, impl.IsFido2WrongDevice(libfido2.ErrInvalidCredential))
	require.True(t, impl.IsFido2WrongDevice(fmt.Errorf("wrap: %w", libfido2.ErrNoCredentials)))

	require.False(t, impl.IsFido2WrongDevice(nil))
	require.False(t, impl.IsFido2WrongDevice(libfido2.ErrPinInvalid))
	require.False(t, impl.IsFido2WrongDevice(errors.New("some other error")))
}

func TestIsFido2PinRequired(t *testing.T) {
	impl := &fido2Impl{}

	require.True(t, impl.IsFido2PinRequired(libfido2.ErrPinRequired))
	require.True(t, impl.IsFido2PinRequired(fmt.Errorf("wrap: %w", libfido2.ErrPinRequired)))

	require.False(t, impl.IsFido2PinRequired(nil))
	require.False(t, impl.IsFido2PinRequired(libfido2.ErrPinInvalid))
	require.False(t, impl.IsFido2PinRequired(libfido2.ErrNoCredentials))
}

func TestIsFido2PinInvalid(t *testing.T) {
	impl := &fido2Impl{}

	// FIDO_ERR_PIN_INVALID (49) — mapped sentinel.
	require.True(t, impl.IsFido2PinInvalid(libfido2.ErrPinInvalid))
	require.True(t, impl.IsFido2PinInvalid(fmt.Errorf("wrap: %w", libfido2.ErrPinInvalid)))

	// FIDO_ERR_PIN_AUTH_INVALID (51) — unmapped, generic error string.
	require.True(t, impl.IsFido2PinInvalid(libfido2.Error{Code: 51}))
	require.True(t, impl.IsFido2PinInvalid(errors.New("libfido2 error 51")))

	// FIDO_ERR_UV_INVALID (63) — unmapped, generic error string.
	require.True(t, impl.IsFido2PinInvalid(libfido2.Error{Code: 63}))
	require.True(t, impl.IsFido2PinInvalid(errors.New("libfido2 error 63")))

	require.False(t, impl.IsFido2PinInvalid(nil))
	require.False(t, impl.IsFido2PinInvalid(errors.New("libfido2 error 50"))) // PIN blocked
	require.False(t, impl.IsFido2PinInvalid(errors.New("libfido2 error 47"))) // touch timeout
	require.False(t, impl.IsFido2PinInvalid(errors.New("some other error")))
}

func TestIsFido2TouchTimeout(t *testing.T) {
	impl := &fido2Impl{}

	// Device-side timeout: mapped sentinel.
	require.True(t, impl.IsFido2TouchTimeout(libfido2.ErrActionTimeout))
	require.True(t, impl.IsFido2TouchTimeout(fmt.Errorf("wrapped: %w", libfido2.ErrActionTimeout)))

	// Host-side timeout: unmapped, surfaces as the generic Error{Code: 47} string.
	require.True(t, impl.IsFido2TouchTimeout(libfido2.Error{Code: 47}))
	require.True(t, impl.IsFido2TouchTimeout(fmt.Errorf("wrapped: libfido2 error 47")))

	require.False(t, impl.IsFido2TouchTimeout(nil))
	require.False(t, impl.IsFido2TouchTimeout(errors.New("libfido2 error 50"))) // PIN blocked
	require.False(t, impl.IsFido2TouchTimeout(errors.New("libfido2 error 54"))) // PIN required (distinct case)
	require.False(t, impl.IsFido2TouchTimeout(errors.New("some other error")))
}
