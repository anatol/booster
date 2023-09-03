package main

/*
#cgo CFLAGS: -I/usr/include/
#cgo LDFLAGS: -lfido2
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

// fields correspond to metadata that should be in the LUKS header because of systemd-cryptenroll
type AssertionOpts struct {
	UV       OptionValue // "fido2-uv-required"
	UP       OptionValue // "fido2-up-required"
	HMACSalt []byte      // "fido2-salt"
}

type Assertion struct {
	HMACSecret []byte
}

type Device struct {
	path string
	dev  *C.fido_dev_t
	sync.Mutex
}

// these errors were documented by go-libfido2, but not all of them were
// see link for full list
// - https://github.com/Yubico/libfido2/blob/main/src/fido/err.h
var libfido2Errors = map[C.int]error{
	C.FIDO_ERR_TX:                     fmt.Errorf("tx error"), // if there was an error transmitting.
	C.FIDO_ERR_RX:                     fmt.Errorf("rx error"), // if there was an error receiving.
	C.FIDO_ERR_INVALID_ARGUMENT:       fmt.Errorf("invalid argument"),
	C.FIDO_ERR_USER_PRESENCE_REQUIRED: fmt.Errorf("user presence required"),
	C.FIDO_ERR_INVALID_COMMAND:        fmt.Errorf("invalid command"),
	C.FIDO_ERR_INVALID_LENGTH:         fmt.Errorf("invalid length"), // if the assertion parameters' length is incorrect
	C.FIDO_ERR_MISSING_PARAMETER:      fmt.Errorf("missing parameter"),
	C.FIDO_ERR_NOT_ALLOWED:            fmt.Errorf("not allowed"),
	C.FIDO_ERR_ACTION_TIMEOUT:         fmt.Errorf("action timed out"),
	C.FIDO_ERR_PIN_NOT_SET:            fmt.Errorf("pin not set"),
	C.FIDO_ERR_INVALID_CREDENTIAL:     fmt.Errorf("invalid credential"),
	C.FIDO_ERR_UNSUPPORTED_OPTION:     fmt.Errorf("unsupported option"),
	C.FIDO_ERR_PIN_INVALID:            fmt.Errorf("pin invalid"),
	C.FIDO_ERR_RX_NOT_CBOR:            fmt.Errorf("rx not CBOR"),
	C.FIDO_ERR_INTERNAL:               fmt.Errorf("internal error"), // if the device name or path is incorrect
	C.FIDO_ERR_PIN_POLICY_VIOLATION:   fmt.Errorf("pin policy violation"),
	C.FIDO_ERR_NO_CREDENTIALS:         fmt.Errorf("no credentials"),
	C.FIDO_ERR_PIN_AUTH_BLOCKED:       fmt.Errorf("pin auth blocked"), // if too many PIN failures.
	C.FIDO_ERR_PIN_REQUIRED:           fmt.Errorf("pin required"),
	C.FIDO_ERR_UP_REQUIRED:            fmt.Errorf("up required"),
	C.FIDO_ERR_RX_INVALID_CBOR:        fmt.Errorf("rx invalid cbor"),
	C.FIDO_ERR_OPERATION_DENIED:       fmt.Errorf("operation denied"),
	C.FIDO_ERR_KEEPALIVE_CANCEL:       fmt.Errorf("keep alive cancel"),
	C.FIDO_ERR_INVALID_OPTION:         fmt.Errorf("invalid option"),
	C.FIDO_ERR_ERR_OTHER:              fmt.Errorf("other error"),
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

func newFido2Device(path string) *Device {
	return &Device{
		path: path,
	}
}

func (d *Device) openFido2Device() (*C.fido_dev_t, error) {
	dev := C.fido_dev_new()
	cPath := C.CString(d.path)
	defer C.free(unsafe.Pointer(cPath))
	if cErr := C.fido_dev_open(dev, cPath); cErr != C.FIDO_OK {
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

// retrieves the internal C value associated with the FIDO2 assertion option
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

// asserts the FIDO2 token then returns the HMAC secret if successful
// see the libfido2 manual for more information about various functions used
// - https://developers.yubico.com/libfido2/Manuals/
func (d *Device) assertFido2Device(
	rpID string,
	clientDataHash []byte,
	credentialID []byte,
	pin string,
	opts *AssertionOpts, ch chan string) (*Assertion, error) {
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
	cRelyingParty := C.CString(rpID)
	defer C.free(unsafe.Pointer(cRelyingParty))
	if cErr := C.fido_assert_set_rp(cAssert, cRelyingParty); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set up assertion relying party id: %w", libfido2Errors[cErr])
	}

	// client data hash
	if cErr := C.fido_assert_set_clientdata_hash(cAssert, getCBytes(clientDataHash), getCLen(clientDataHash)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set client data hash: %w", libfido2Errors[cErr])
	}

	// credential id
	if cErr := C.fido_assert_allow_cred(cAssert, getCBytes(credentialID), getCLen(credentialID)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set allowed credentials: %w", libfido2Errors[cErr])
	}

	// extension
	ext := 0
	ext |= int(C.FIDO_EXT_HMAC_SECRET)
	if cErr := C.fido_assert_set_extensions(cAssert, C.int(ext)); cErr != C.FIDO_OK {
		return nil, fmt.Errorf("failed to set extensions: %w", libfido2Errors[cErr])
	}

	// options
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

	// hmac salt
	if opts.HMACSalt != nil {
		if cErr := C.fido_assert_set_hmac_salt(cAssert, getCBytes(opts.HMACSalt), getCLen(opts.HMACSalt)); cErr != C.FIDO_OK {
			return nil, fmt.Errorf("failed to set hmac salt: %w", libfido2Errors[cErr])
		}
	}

	// pin
	// nil means a pin is not required
	var cPin *C.char = nil
	if pin != "" {
		cPin = C.CString(pin)
		defer C.free(unsafe.Pointer(cPin))
	}

	// assert the device
	ch <- "Please confirm user presence or verify " + d.path + ":"
	if cErr := C.fido_dev_get_assert(dev, cAssert, cPin); cErr != C.FIDO_OK {
		ch <- "Failed to get assertion for " + d.path
		// cancels all pending requests for the device
		C.fido_dev_cancel(dev)
		return nil, fmt.Errorf("failed to get assertion: %w", libfido2Errors[cErr])
	}

	if opts.UP == True {
		ch <- "User presence confirmed"
	}
	if opts.UV == True {
		ch <- "User verification confirmed"
	}

	cIdx := C.size_t(0)

	// extract the hmac secret
	cHMACLen := C.fido_assert_hmac_secret_len(cAssert, cIdx)
	cHMACPtr := C.fido_assert_hmac_secret_ptr(cAssert, cIdx)
	hmacSecret := C.GoBytes(unsafe.Pointer(cHMACPtr), C.int(cHMACLen))

	return &Assertion{HMACSecret: hmacSecret}, nil
}

func GetFido2HMACSecret(
	devName string,
	rpID string,
	clientDataHash []byte,
	credentialID []byte,
	pin string,
	hmacSalt []byte,
	userPresenceRequired bool,
	userVerificationRequired bool,
	ch chan string) ([]byte, error) {
	defer close(ch)

	dev := newFido2Device("/dev/" + devName)

	isFido2, err := dev.isFido2()
	if err != nil {
		return nil, fmt.Errorf("HID %s does not support FIDO: "+err.Error(), devName)
	}
	if !isFido2 {
		return nil, fmt.Errorf("HID %s does not support FIDO, continuing", devName)
	}

	assertOpts := &AssertionOpts{
		HMACSalt: hmacSalt,
		UP:       Default,
		UV:       Default,
	}

	if userPresenceRequired {
		assertOpts.UP = True
	}

	if userVerificationRequired {
		assertOpts.UV = True
	}

	assert, err := dev.assertFido2Device(rpID, clientDataHash, credentialID, pin, assertOpts, ch)
	if err != nil {
		return nil, err
	}

	return assert.HMACSecret, nil
}
