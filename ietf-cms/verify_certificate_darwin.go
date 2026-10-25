//go:build darwin && cgo

package cms

/*
#cgo LDFLAGS: -framework CoreFoundation -framework Security
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

static void cmsAppend(CFMutableArrayRef array, SecCertificateRef cert) {
 CFArrayAppendValue(array, cert);
}

static SecCertificateRef cmsCertificate(const void *bytes, CFIndex length) {
 CFDataRef data = CFDataCreate(NULL, bytes, length);
 if (!data) return NULL;
 SecCertificateRef cert = SecCertificateCreateWithData(NULL, data);
 CFRelease(data);
 return cert;
}

// Basic X.509 checks native trust settings without imposing TLS-server EKU,
// hostname, or maximum TLS lifetime requirements on document signatures.
static CFArrayRef cmsEvaluate(CFArrayRef certs, double when, CFIndex *code, CFStringRef *message) {
 SecPolicyRef policy = SecPolicyCreateBasicX509();
 SecTrustRef trust = NULL;
 OSStatus status = SecTrustCreateWithCertificates(certs, policy, &trust);
 CFRelease(policy);
 if (status != errSecSuccess) { *code = status; return NULL; }
 CFDateRef date = CFDateCreate(NULL, when);
 status = SecTrustSetVerifyDate(trust, date);
 CFRelease(date);
 if (status == errSecSuccess) status = SecTrustSetNetworkFetchAllowed(trust, false);
 if (status != errSecSuccess) { *code = status; CFRelease(trust); return NULL; }
 CFErrorRef error = NULL;
 if (!SecTrustEvaluateWithError(trust, &error)) {
  *code = error ? CFErrorGetCode(error) : errSecInternalComponent;
  if (error) { *message = CFErrorCopyDescription(error); CFRelease(error); }
  CFRelease(trust);
  return NULL;
 }
 CFArrayRef chain = SecTrustCopyCertificateChain(trust);
 CFRelease(trust);
 return chain;
}
*/
import "C"

import (
	"crypto/x509"
	"fmt"
	"time"
	"unsafe"
)

func verifyCertificate(cert *x509.Certificate, supplied []*x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
	// Respect explicit caller roots. Do not silently add the machine's trust to
	// a caller-provided store. SystemCertPool on Darwin is an opaque marker.
	if opts.Roots != nil {
		system, err := x509.SystemCertPool()
		if err != nil || !opts.Roots.Equal(system) {
			return cert.Verify(opts)
		}
	}
	chain, err := nativeCertificateChain(cert, supplied, opts.CurrentTime)
	if err != nil {
		return nil, err
	}
	// Recheck Go's constraints (including requested EKUs, DNSName and critical
	// extensions) with only the anchor already accepted by macOS. A fresh pool
	// selects Go's non-TLS verifier; an embedded certificate is never an anchor
	// unless the native trust evaluation above actually accepted it.
	opts.Roots = x509.NewCertPool()
	opts.Roots.AddCert(chain[len(chain)-1])
	if opts.Intermediates == nil {
		opts.Intermediates = x509.NewCertPool()
	} else {
		opts.Intermediates = opts.Intermediates.Clone()
	}
	for _, c := range chain[1:] {
		opts.Intermediates.AddCert(c)
	}
	return cert.Verify(opts)
}

func nativeCertificateChain(cert *x509.Certificate, supplied []*x509.Certificate, when time.Time) ([]*x509.Certificate, error) {
	array := C.CFArrayCreateMutable(0, 0, &C.kCFTypeArrayCallBacks)
	if array == 0 {
		return nil, fmt.Errorf("x509: cannot allocate native certificate array")
	}
	defer C.CFRelease(C.CFTypeRef(array))
	all := append([]*x509.Certificate{cert}, supplied...)
	for _, c := range all {
		if len(c.Raw) == 0 {
			return nil, fmt.Errorf("x509: empty certificate")
		}
		ref := C.cmsCertificate(unsafe.Pointer(&c.Raw[0]), C.CFIndex(len(c.Raw)))
		if ref == 0 {
			return nil, fmt.Errorf("x509: invalid native certificate")
		}
		C.cmsAppend(array, ref)
		C.CFRelease(C.CFTypeRef(ref))
	}
	if when.IsZero() {
		when = time.Now()
	}
	var code C.CFIndex
	var message C.CFStringRef
	chainRef := C.cmsEvaluate(C.CFArrayRef(array), C.double(float64(when.Unix())-978307200), &code, &message)
	detail := "native Basic X.509 trust evaluation failed"
	if message != 0 {
		defer C.CFRelease(C.CFTypeRef(message))
		size := C.CFStringGetMaximumSizeForEncoding(C.CFStringGetLength(message), C.kCFStringEncodingUTF8) + 1
		buf := make([]byte, int(size))
		if C.CFStringGetCString(message, (*C.char)(unsafe.Pointer(&buf[0])), size, C.kCFStringEncodingUTF8) != 0 {
			detail = C.GoString((*C.char)(unsafe.Pointer(&buf[0])))
		}
	}
	if chainRef == 0 {
		switch code {
		case C.errSecNotTrusted, C.errSecCreateChainFailed:
			return nil, x509.UnknownAuthorityError{Cert: cert}
		case C.errSecCertificateExpired, C.errSecCertificateNotValidYet:
			return nil, x509.CertificateInvalidError{Cert: cert, Reason: x509.Expired, Detail: detail}
		default:
			return nil, fmt.Errorf("x509: native trust error %d: %s", code, detail)
		}
	}
	defer C.CFRelease(C.CFTypeRef(chainRef))
	var chain []*x509.Certificate
	for i := C.CFIndex(0); i < C.CFArrayGetCount(chainRef); i++ {
		ref := C.SecCertificateRef(C.CFArrayGetValueAtIndex(chainRef, i))
		data := C.SecCertificateCopyData(ref)
		if data == 0 {
			return nil, fmt.Errorf("x509: cannot export native chain")
		}
		raw := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(C.CFDataGetLength(data)))
		C.CFRelease(C.CFTypeRef(data))
		parsed, err := x509.ParseCertificate(raw)
		if err != nil {
			return nil, err
		}
		chain = append(chain, parsed)
	}
	if len(chain) == 0 {
		return nil, fmt.Errorf("x509: native trust returned an empty chain")
	}
	return chain, nil
}
