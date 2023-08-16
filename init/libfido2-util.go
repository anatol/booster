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
	"unsafe"
)

const (
	Default OptionValue = ""
	True    OptionValue = "true"
	False   OptionValue = "false"
)

const (
	HMACSecretExtension  Extension = "hmac-secret"
	CredProtectExtension Extension = "credProtect"
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

type OptionValue string

type Extension string

// FIDO2 assertions options that should be in the LUKS header because of systemd-cryptenroll
type AssertionOpts struct {
	Extensions []Extension
	UV         OptionValue
	UP         OptionValue
	HMACSalt   []byte
}

type User struct {
	ID          []byte
	Name        string
	DisplayName string
	Icon        string
}

type Assertion struct {
	HMACSecret []byte
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

func getCOpt(o OptionValue) (C.fido_opt_t, error) {
	switch o {
	case Default:
		return C.FIDO_OPT_OMIT, nil
	case True:
		return C.FIDO_OPT_TRUE, nil
	case False:
		return C.FIDO_OPT_FALSE, nil
	default:
		return C.FIDO_OPT_OMIT, fmt.Errorf("invalid credential protection")
	}
}

func getCLen(b []byte) C.size_t {
	return C.size_t(len(b))
}

func getCBytes(b []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

func getExtensionsInt(extensions []Extension) int {
	exts := 0
	for _, extension := range extensions {
		switch extension {
		case HMACSecretExtension:
			exts |= int(C.FIDO_EXT_HMAC_SECRET)
		case CredProtectExtension:
			exts |= int(C.FIDO_EXT_CRED_PROTECT)
		}
	}
	return exts
}

// expects the FIDO2 pin
// nil means a pin is not required
func getCStringOrNil(s string) *C.char {
	if s == "" {
		return nil
	}
	return C.CString(s)
}

func (d *Device) AssertFido2Device(
	rpID string,
	clientDataHash []byte,
	credentialIDs [][]byte,
	pin string,
	opts *AssertionOpts) (*Assertion, error) {

	dev, err := d.openFido2Device()
	if err != nil {
		return nil, err
	}
	defer d.closeFido2Device(dev)

	if opts == nil {
		opts = &AssertionOpts{}
	}
	if rpID == "" {
		return nil, fmt.Errorf("no relying party id specified")
	}

	cAssert := C.fido_assert_new()
	defer C.fido_assert_free(&cAssert)

	// relying party
	if cErr := C.fido_assert_set_rp(cAssert, C.CString(rpID)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set up assertion relying party id: %w", errFromCode(cErr))
	}
	// client data hash
	if cErr := C.fido_assert_set_clientdata_hash(cAssert, getCBytes(clientDataHash), getCLen(clientDataHash)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set client data hash: %w", errFromCode(cErr))
	}
	// credential id
	for _, credentialID := range credentialIDs {
		if cErr := C.fido_assert_allow_cred(cAssert, getCBytes(credentialID), getCLen(credentialID)); cErr != C.FIDO_OK {
			return nil, fmt.Errorf("failed to set allowed credentials: %w", errFromCode(cErr))
		}
	}
	// extension
	if exts := getExtensionsInt(opts.Extensions); exts > 0 {
		if cErr := C.fido_assert_set_extensions(cAssert, C.int(exts)); cErr != C.FIDO_OK {
			return nil, fmt.Errorf("failed to set extensions: %w", errFromCode(cErr))
		}
	}
	// options
	cUV, err := getCOpt(opts.UV)
	if err != nil {
		return nil, err
	}
	if cErr := C.fido_assert_set_uv(cAssert, cUV); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set UV option: %w", errFromCode(cErr))
	}
	cUP, err := getCOpt(opts.UP)
	if err != nil {
		return nil, err
	}
	if cErr := C.fido_assert_set_up(cAssert, cUP); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set UP option: %w", errFromCode(cErr))
	}
	// hmac
	if opts.HMACSalt != nil {
		if cErr := C.fido_assert_set_hmac_salt(cAssert, getCBytes(opts.HMACSalt), getCLen(opts.HMACSalt)); cErr != C.FIDO_OK {
			return nil, fmt.Errorf("failed to set hmac salt: %w", errFromCode(cErr))
		}
	}

	// assert
	if cErr := C.fido_dev_get_assert(dev, cAssert, getCStringOrNil(pin)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to get assertion: %w", errFromCode(cErr))
	}

	cIdx := C.size_t(0)

	cHMACLen := C.fido_assert_hmac_secret_len(cAssert, cIdx)
	cHMACPtr := C.fido_assert_hmac_secret_ptr(cAssert, cIdx)
	hmacSecret := C.GoBytes(unsafe.Pointer(cHMACPtr), C.int(cHMACLen))

	assertion := &Assertion{
		HMACSecret: hmacSecret,
	}
	return assertion, nil
}