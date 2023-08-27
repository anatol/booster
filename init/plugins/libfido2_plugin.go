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

type OptionValue string

// fido2 assertions options that should be in the LUKS header because of systemd-cryptenroll
type AssertionOpts struct {
	UV       OptionValue
	UP       OptionValue
	HMACSalt []byte
}

type Assertion struct {
	HMACSecret []byte
}

// fido2 Device
type Device struct {
	path string
	dev  *C.fido_dev_t
	sync.Mutex
}

// map is used during errors when setting inputs during fido2 assertion
// returns errors associated with the status codes returned from C
// these errors were documented by go-libfido2, but not all of them were
// see link for full list
// - https://github.com/Yubico/libfido2/blob/main/src/fido/err.h
var libfido2Errors = map[C.int]error{
	// if there was an error transmitting.
	C.FIDO_ERR_TX: fmt.Errorf("tx error"),
	// if there was an error receiving.
	C.FIDO_ERR_RX: fmt.Errorf("rx error"),
	// if arguments are invalid.
	C.FIDO_ERR_INVALID_ARGUMENT: fmt.Errorf("invalid argument"), // -7
	// if user presence required.
	C.FIDO_ERR_USER_PRESENCE_REQUIRED: fmt.Errorf("user presence required"), // -8
	// if command is not supported.
	C.FIDO_ERR_INVALID_COMMAND: fmt.Errorf("invalid command"), // 0x01
	// if invalid length.
	// can happen if hmac or credential id are not base64 decoded
	C.FIDO_ERR_INVALID_LENGTH: fmt.Errorf("invalid length"), // 0x03
	// if missing parameter.
	C.FIDO_ERR_MISSING_PARAMETER: fmt.Errorf("missing parameter"), // 0x14)
	// if not allowed.
	C.FIDO_ERR_NOT_ALLOWED: fmt.Errorf("not allowed"),
	// if action timed out.
	C.FIDO_ERR_ACTION_TIMEOUT: fmt.Errorf("action timed out"),
	// if PIN is not set and is required for command.
	C.FIDO_ERR_PIN_NOT_SET: fmt.Errorf("pin not set"),
	// if credential is invalid.
	C.FIDO_ERR_INVALID_CREDENTIAL: fmt.Errorf("invalid credential"),
	// if option is unsupported.
	C.FIDO_ERR_UNSUPPORTED_OPTION: fmt.Errorf("unsupported option"),
	// if pin is wrong.
	C.FIDO_ERR_PIN_INVALID: fmt.Errorf("pin invalid"),
	// rx not CBOR.
	C.FIDO_ERR_RX_NOT_CBOR: fmt.Errorf("rx not CBOR"),
	// internal error.
	C.FIDO_ERR_INTERNAL: fmt.Errorf("internal error"),
	// if PIN policy violation.
	C.FIDO_ERR_PIN_POLICY_VIOLATION: fmt.Errorf("pin policy violation"),
	// if no credentials.
	C.FIDO_ERR_NO_CREDENTIALS: fmt.Errorf("no credentials"),
	// if too many PIN failures.
	C.FIDO_ERR_PIN_AUTH_BLOCKED: fmt.Errorf("pin auth blocked"),
	// if PIN is required.
	C.FIDO_ERR_PIN_REQUIRED: fmt.Errorf("pin required"),
	// if user presence is required.
	C.FIDO_ERR_UP_REQUIRED: fmt.Errorf("up required"),
	// if receiving invalid CBOR.
	C.FIDO_ERR_RX_INVALID_CBOR: fmt.Errorf("rx invalid cbor"),
	// if operation denied.
	C.FIDO_ERR_OPERATION_DENIED: fmt.Errorf("operation denied"),
	// if action was cancelled.
	C.FIDO_ERR_KEEPALIVE_CANCEL: fmt.Errorf("keep alive cancel"),
	// if option is invalid.
	C.FIDO_ERR_INVALID_OPTION: fmt.Errorf("invalid option"),
	C.FIDO_ERR_ERR_OTHER:      fmt.Errorf("other error"),
}

/*
	initiliaze the library

The fido_init() function initialises the libfido2 library. Its invocation must precede that of any other libfido2 function in the context of the executing thread.
If FIDO_DEBUG is set in flags, then debug output will be emitted by libfido2 on stderr. Alternatively, the FIDO_DEBUG environment variable may be set.
If FIDO_DISABLE_U2F_FALLBACK is set in flags, then libfido2 will not fallback to U2F in fido_dev_open(3) if a device claims to support FIDO2 but fails to respond to a CTAP 2.0 greeting.

- https://developers.yubico.com/libfido2/Manuals/fido_init.html
*/
func init() {
	C.fido_init(0) // initiliaze the library without debugging
}

// Public
func newFido2Device(path string) *Device {
	return &Device{
		path: path,
	}
}

func (d *Device) openFido2Device() (*C.fido_dev_t, error) {
	dev := C.fido_dev_new()
	if cErr := C.fido_dev_open(dev, C.CString(d.path)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to open hidraw device: %w", libfido2Errors[cErr])
	}
	d.dev = dev

	return dev, nil
}

func (d *Device) closeFido2Device(dev *C.fido_dev_t) {
	d.Lock()
	d.dev = nil
	d.Unlock()
	if cErr := C.fido_dev_close(dev); cErr != C.FIDO_OK {
		fmt.Println("failed to close hidraw device: %w", libfido2Errors[cErr])
	}
	C.fido_dev_free(&dev)
}

func (d *Device) isFido2() (bool, error) {
	dev, err := d.openFido2Device()
	if err != nil {
		return false, err
	}
	defer d.closeFido2Device(dev)
	isFido2 := bool(C.fido_dev_is_fido2(dev))

	return isFido2, nil
}

// retrieves the c value associated with the fido2 assertion option
func getCOpt(o OptionValue) (C.fido_opt_t, error) {
	switch o {
	case Default:
		return C.FIDO_OPT_OMIT, nil
	case True:
		return C.FIDO_OPT_TRUE, nil
	case False:
		return C.FIDO_OPT_FALSE, nil
	default:
		// custom error
		return C.FIDO_OPT_OMIT, fmt.Errorf("invalid credential protection")
	}
}

func getCLen(b []byte) C.size_t {
	return C.size_t(len(b))
}

func getCBytes(b []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}

// expects the fido2 pin
// nil means a pin is not required
func getCStringOrNil(s string) *C.char {
	if s == "" {
		return nil
	}

	return C.CString(s)
}

// asserts the fido2 token then returns the hmac secret if successful
// see the libfido2 manual for more information about various functions used
// - https://developers.yubico.com/libfido2/Manuals/
func (d *Device) assertFido2Device(
	rpID string,
	clientDataHash []byte,
	credentialID []byte,
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

	// set the relying party
	if cErr := C.fido_assert_set_rp(cAssert, C.CString(rpID)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set up assertion relying party id: %w", libfido2Errors[cErr])
	}

	// set the client data hash
	if cErr := C.fido_assert_set_clientdata_hash(cAssert, getCBytes(clientDataHash), getCLen(clientDataHash)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set client data hash: %w", libfido2Errors[cErr])
	}

	// set the credential id
	if cErr := C.fido_assert_allow_cred(cAssert, getCBytes(credentialID), getCLen(credentialID)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set allowed credentials: %w", libfido2Errors[cErr])
	}

	// set the extension
	ext := 0
	ext |= int(C.FIDO_EXT_HMAC_SECRET)
	if cErr := C.fido_assert_set_extensions(cAssert, C.int(ext)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set extensions: %w", libfido2Errors[cErr])
	}

	// set the options
	cUV, err := getCOpt(opts.UV)
	if err != nil {
		return nil, err
	}
	if cErr := C.fido_assert_set_uv(cAssert, cUV); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set UV option: %w", libfido2Errors[cErr])
	}
	cUP, err := getCOpt(opts.UP)
	if err != nil {
		return nil, err
	}
	if cErr := C.fido_assert_set_up(cAssert, cUP); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set UP option: %w", libfido2Errors[cErr])
	}

	// set the hmac salt
	if opts.HMACSalt != nil {
		if cErr := C.fido_assert_set_hmac_salt(cAssert, getCBytes(opts.HMACSalt), getCLen(opts.HMACSalt)); cErr != C.FIDO_OK {
			return nil, fmt.Errorf("failed to set hmac salt: %w", libfido2Errors[cErr])
		}
	}

	// assert the device
	if cErr := C.fido_dev_get_assert(dev, cAssert, getCStringOrNil(pin)); cErr != C.FIDO_OK {
		// cancels all pending requests for the device
		C.fido_dev_cancel(dev)
		return nil, fmt.Errorf("failed to get assertion: %w", libfido2Errors[cErr])
	}

	cIdx := C.size_t(0)

	// extract the hmac secret
	// - https://developers.yubico.com/libfido2/Manuals/fido_assert_largeblob_key_ptr.html
	cHMACLen := C.fido_assert_hmac_secret_len(cAssert, cIdx)
	cHMACPtr := C.fido_assert_hmac_secret_ptr(cAssert, cIdx)
	hmacSecret := C.GoBytes(unsafe.Pointer(cHMACPtr), C.int(cHMACLen))

	/* assertion := &Assertion{
		HMACSecret: hmacSecret,
	} */

	assertion := &Assertion{HMACSecret: hmacSecret}

	return assertion, nil
}

func GetFido2HMACSecret(devName string,
	rpID string,
	clientDataHash []byte,
	credentialID []byte,
	pin string,
	hmacSalt []byte, userPresenceRequired bool, userVerificationRequired bool) ([]byte, error) {
	dev := newFido2Device("/dev/" + devName)

	isFido2, err := dev.isFido2()
	if err != nil {
		return nil, fmt.Errorf("HID %s does not support FIDO: "+err.Error(), devName)
	}
	if !isFido2 {
		return nil, fmt.Errorf("HID %s does not support FIDO, continuing", devName)
	}

	/* set the options */
	assertOpts := &AssertionOpts{
		HMACSalt: hmacSalt, UP: Default, UV: Default}

	if userPresenceRequired {
		assertOpts.UP = True
	}

	if userVerificationRequired {
		assertOpts.UV = True
	}

	assert, err := dev.assertFido2Device(rpID, clientDataHash, credentialID, pin, assertOpts)

	if err != nil {
		return nil, err
	}

	return assert.HMACSecret, nil
}
