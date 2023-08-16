package main

/*
#cgo CFLAGS: -I/usr/include/
#cgo LDFLAGS: -lfido2
#include <stdio.h>
#include <stdlib.h>
#include <fido.h>
*/
import "C"
import (
	"fmt"
	"sync"
)

const (
	// ErrInvalidArgument if arguments are invalid.
	ErrInvalidArgument = "invalid argument"
	// ErrUserPresenceRequired is user presence required.
	ErrUserPresenceRequired = "user presence required"
	// ErrTX if there was an error transmitting.
	ErrTX = "tx error"
	// ErrRX if there was an error receiving.
	ErrRX = "rx error"
	// ErrNotAllowed if not allowed.
	ErrNotAllowed = "not allowed"
	// ErrActionTimeout if action timed out.
	ErrActionTimeout = "action timed out"
	// ErrPinNotSet if PIN is not set and is required for command.
	ErrPinNotSet = "pin not set"
	// ErrInvalidCommand if command is not supported.
	ErrInvalidCommand = "invalid command"
	// ErrInvalidLength if invalid length.
	ErrInvalidLength = "invalid length"
	// ErrInvalidCredential if credential is invalid.
	ErrInvalidCredential = "invalid credential"
	// ErrUnsupportedOption if option is unsupported.
	ErrUnsupportedOption = "unsupported option"
	// ErrPinInvalid if pin is wrong.
	ErrPinInvalid = "pin invalid"
	// ErrRXNotCBOR rx not CBOR.
	ErrRXNotCBOR = "rx not CBOR"
	// ErrPinPolicyViolation if PIN policy violation.
	ErrPinPolicyViolation = "pin policy violation"
	// ErrInternal internal error.
	ErrInternal = "internal error"
	// ErrNoCredentials if no credentials.
	ErrNoCredentials = "no credentials"
	// ErrPinAuthBlocked if too many PIN failures.
	ErrPinAuthBlocked = "pin auth blocked"
	// ErrPinRequired if PIN is required.
	ErrPinRequired = "pin required"
	// ErrMissingParameter if missing parameter.
	ErrMissingParameter = "missing parameter"
	// ErrUPRequired if user presence is required.
	ErrUPRequired = "up required"
	// ErrRXInvalidCBOR if receiving invalid CBOR.
	ErrRXInvalidCBOR = "rx invalid cbor"
	// ErrOperationDenied if operation denied.
	ErrOperationDenied = "operation denied"
	// ErrNotFIDO2 if device is not a FIDO2 device.
	ErrNotFIDO2 = "not a FIDO2 device"
	// ErrKeepaliveCancel if action was cancelled.
	ErrKeepaliveCancel = "keep alive cancel"
	// ErrInvalidOption if option is invalid.
	ErrInvalidOption = "invalid option"
	// ErrOther if other error?
	ErrOther = "other error"
)

func errFromCode(code C.int) error {
	// see https://github.com/Yubico/libfido2/blob/main/src/fido/err.h
	switch code {
	case C.FIDO_ERR_TX: // -1
		return fmt.Errorf(ErrTX)
	case C.FIDO_ERR_RX: // -2
		return fmt.Errorf(ErrRX)
	case C.FIDO_ERR_INVALID_ARGUMENT: // -7
		return fmt.Errorf(ErrInvalidArgument)
	case C.FIDO_ERR_USER_PRESENCE_REQUIRED: // -8
		return fmt.Errorf(ErrUserPresenceRequired)
	case C.FIDO_ERR_INVALID_COMMAND: // 0x01
		return fmt.Errorf(ErrInvalidCommand)
	case C.FIDO_ERR_INVALID_LENGTH: // 0x03
		return fmt.Errorf(ErrInvalidLength)
	case C.FIDO_ERR_MISSING_PARAMETER:
		return fmt.Errorf(ErrMissingParameter) // 0x14)
	case C.FIDO_ERR_NOT_ALLOWED:
		return fmt.Errorf(ErrNotAllowed)
	case C.FIDO_ERR_ACTION_TIMEOUT:
		return fmt.Errorf(ErrActionTimeout)
	case C.FIDO_ERR_PIN_NOT_SET:
		return fmt.Errorf(ErrPinNotSet)
	case C.FIDO_ERR_INVALID_CREDENTIAL:
		return fmt.Errorf(ErrInvalidCredential)
	case C.FIDO_ERR_UNSUPPORTED_OPTION:
		return fmt.Errorf(ErrUnsupportedOption)
	case C.FIDO_ERR_PIN_INVALID:
		return fmt.Errorf(ErrPinInvalid)
	case C.FIDO_ERR_RX_NOT_CBOR:
		return fmt.Errorf(ErrRXNotCBOR)
	case C.FIDO_ERR_INTERNAL:
		return fmt.Errorf(ErrInternal)
	case C.FIDO_ERR_PIN_POLICY_VIOLATION:
		return fmt.Errorf(ErrPinPolicyViolation)
	case C.FIDO_ERR_NO_CREDENTIALS:
		return fmt.Errorf(ErrNoCredentials)
	case C.FIDO_ERR_PIN_AUTH_BLOCKED:
		return fmt.Errorf(ErrPinAuthBlocked)
	case C.FIDO_ERR_PIN_REQUIRED:
		return fmt.Errorf(ErrPinRequired)
	case C.FIDO_ERR_UP_REQUIRED:
		return fmt.Errorf(ErrUPRequired)
	case C.FIDO_ERR_RX_INVALID_CBOR:
		return fmt.Errorf(ErrRXInvalidCBOR)
	case C.FIDO_ERR_OPERATION_DENIED:
		return fmt.Errorf(ErrOperationDenied)
	case C.FIDO_ERR_KEEPALIVE_CANCEL:
		return fmt.Errorf(ErrKeepaliveCancel)
	case C.FIDO_ERR_INVALID_OPTION:
		return fmt.Errorf(ErrInvalidOption)
	case C.FIDO_ERR_ERR_OTHER:
		return fmt.Errorf(ErrOther)
	default:
		return fmt.Errorf("libfido2 error %d", code)
	}
}

// FIDO2 Device
type Device struct {
	path string
	dev  *C.fido_dev_t
	sync.Mutex
}

func NewFido2Device(path string) *Device {
	return &Device{
		path: fmt.Sprintf("%s", path),
	}
}

func (d *Device) openFido2Device() (*C.fido_dev_t, error) {
	dev := C.fido_dev_new()
	if cErr := C.fido_dev_open(dev, C.CString(d.path)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to open hidraw device: %w", errFromCode(cErr))
	}
	d.dev = dev
	return dev, nil
}

func (d *Device) closeFido2Device(dev *C.fido_dev_t) {
	d.Lock()
	d.dev = nil
	d.Unlock()
	if cErr := C.fido_dev_close(dev); cErr != C.FIDO_OK {
		info("failed to close hidraw device: ", errFromCode(cErr).Error())
	}
	C.fido_dev_free(&dev)
}

// checks by opening and closing the device
func (d *Device) IsFido2() (bool, error) {
	dev, err := d.openFido2Device()
	if err != nil {
		return false, err
	}
	defer d.closeFido2Device(dev)
	isFido2 := bool(C.fido_dev_is_fido2(dev))
	return isFido2, nil
}
