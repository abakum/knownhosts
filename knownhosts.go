// Package knownhosts is a thin wrapper around golang.org/x/crypto/ssh/knownhosts,
// adding the ability to obtain the list of host key algorithms for a known host.
/*
git checkout certs-backwards-compat
git branch -m main old-main
git branch -m certs-backwards-compat main
*/

package knownhosts

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"
	xknownhosts "golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyDB wraps logic in golang.org/x/crypto/ssh/knownhosts with additional
// behaviors, such as the ability to perform host key/algorithm lookups from the
// known_hosts entries. It fully supports @cert-authority lines as well, and can
// return ssh.CertAlgo* values when looking up algorithms. To create a
// HostKeyDB, use NewDB.
type HostKeyDB struct {
	callback ssh.HostKeyCallback
	isCert   map[string]bool // keyed by "filename:line"
}

// NewDB creates a HostKeyDB from the given OpenSSH known_hosts file(s). It
// reads and parses the provided files one additional time (beyond logic in
// golang.org/x/crypto/ssh/knownhosts) in order to handle CA lines properly.
// When supplying multiple files, their order does not matter.
func NewDB(files ...string) (*HostKeyDB, error) {
	cb, err := xknownhosts.New(files...)
	if err != nil {
		return nil, err
	}
	hkdb := &HostKeyDB{
		callback: cb,
		isCert:   make(map[string]bool),
	}

	// Re-read each file a single time, looking for @cert-authority lines. The
	// logic for reading the file is designed to mimic hostKeyDB.Read from
	// golang.org/x/crypto/ssh/knownhosts
	for _, filename := range files {
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		lineNum := 0
		for scanner.Scan() {
			lineNum++
			line := scanner.Bytes()
			line = bytes.TrimSpace(line)
			// Does the line start with "@cert-authority" followed by whitespace?
			if len(line) > 15 && bytes.HasPrefix(line, []byte("@cert-authority")) && (line[15] == ' ' || line[15] == '\t') {
				mapKey := fmt.Sprintf("%s:%d", filename, lineNum)
				hkdb.isCert[mapKey] = true
			}
		}
		if err := scanner.Err(); err != nil {
			return nil, fmt.Errorf("knownhosts: %s:%d: %w", filename, lineNum, err)
		}
	}
	return hkdb, nil
}

// HostKeyCallback returns an ssh.HostKeyCallback for use in
// ssh.ClientConfig.HostKeyCallback.
func (hkdb *HostKeyDB) HostKeyCallback() ssh.HostKeyCallback {
	return hkdb.callback
}

// PublicKey wraps ssh.PublicKey with an additional field, to identify
// whether they key corresponds to a certificate authority.
type PublicKey struct {
	ssh.PublicKey
	Cert bool
}

// HostKeys returns a slice of known host public keys for the supplied host:port
// found in the known_hosts file(s), or an empty slice if the host is not
// already known. For hosts that have multiple known_hosts entries (for
// different key types), the result will be sorted by known_hosts filename and
// line number.
func (hkdb *HostKeyDB) HostKeys(hostWithPort string) (keys []PublicKey) {
	var keyErr *xknownhosts.KeyError
	placeholderAddr := &net.TCPAddr{IP: []byte{0, 0, 0, 0}}
	placeholderPubKey := &fakePublicKey{}
	var kkeys []xknownhosts.KnownKey
	if hkcbErr := hkdb.callback(hostWithPort, placeholderAddr, placeholderPubKey); errors.As(hkcbErr, &keyErr) {
		kkeys = append(kkeys, keyErr.Want...)
		knownKeyLess := func(i, j int) bool {
			if kkeys[i].Filename < kkeys[j].Filename {
				return true
			}
			return (kkeys[i].Filename == kkeys[j].Filename && kkeys[i].Line < kkeys[j].Line)
		}
		sort.Slice(kkeys, knownKeyLess)
		keys = make([]PublicKey, len(kkeys))
		for n := range kkeys {
			keys[n] = PublicKey{
				PublicKey: kkeys[n].Key,
			}
			if len(hkdb.isCert) > 0 {
				keys[n].Cert = hkdb.isCert[fmt.Sprintf("%s:%d", kkeys[n].Filename, kkeys[n].Line)]
			}
		}
	}
	return keys
}

// HostKeyAlgorithms returns a slice of host key algorithms for the supplied
// host:port found in the known_hosts file(s), or an empty slice if the host
// is not already known. The result may be used in ssh.ClientConfig's
// HostKeyAlgorithms field, either as-is or after filtering (if you wish to
// ignore or prefer particular algorithms). For hosts that have multiple
// known_hosts entries (of different key types), the result will be sorted by
// known_hosts filename and line number.
// For @cert-authority lines, the returned algorithm will be the correct
// ssh.CertAlgo* value.
func (hkdb *HostKeyDB) HostKeyAlgorithms(hostWithPort string) (algos []string) {
	// We ensure that algos never contains duplicates. This is done for robustness
	// even though currently golang.org/x/crypto/ssh/knownhosts never exposes
	// multiple keys of the same type. This way our behavior here is unaffected
	// even if https://github.com/golang/go/issues/28870 is implemented, for
	// example by https://github.com/golang/crypto/pull/254.
	hostKeys := hkdb.HostKeys(hostWithPort)
	seen := make(map[string]struct{}, len(hostKeys))
	addAlgo := func(typ string, cert bool) {
		if cert {
			typ = keyTypeToCertAlgo(typ)
		}
		if _, already := seen[typ]; !already {
			algos = append(algos, typ)
			seen[typ] = struct{}{}
		}
	}
	for _, key := range hostKeys {
		typ := key.Type()
		if typ == ssh.KeyAlgoRSA {
			// KeyAlgoRSASHA256 and KeyAlgoRSASHA512 are only public key algorithms,
			// not public key formats, so they can't appear as a PublicKey.Type.
			// The corresponding PublicKey.Type is KeyAlgoRSA. See RFC 8332, Section 2.
			addAlgo(ssh.KeyAlgoRSASHA512, key.Cert)
			addAlgo(ssh.KeyAlgoRSASHA256, key.Cert)
		}
		addAlgo(typ, key.Cert)
	}
	return algos
}

func keyTypeToCertAlgo(keyType string) string {
	switch keyType {
	case ssh.KeyAlgoRSA:
		return ssh.CertAlgoRSAv01
	case ssh.KeyAlgoRSASHA256:
		return ssh.CertAlgoRSASHA256v01
	case ssh.KeyAlgoRSASHA512:
		return ssh.CertAlgoRSASHA512v01
	case ssh.KeyAlgoDSA:
		return ssh.CertAlgoDSAv01
	case ssh.KeyAlgoECDSA256:
		return ssh.CertAlgoECDSA256v01
	case ssh.KeyAlgoSKECDSA256:
		return ssh.CertAlgoSKECDSA256v01
	case ssh.KeyAlgoECDSA384:
		return ssh.CertAlgoECDSA384v01
	case ssh.KeyAlgoECDSA521:
		return ssh.CertAlgoECDSA521v01
	case ssh.KeyAlgoED25519:
		return ssh.CertAlgoED25519v01
	case ssh.KeyAlgoSKED25519:
		return ssh.CertAlgoSKED25519v01
	}
	return ""
}

// HostKeyCallback wraps ssh.HostKeyCallback with an additional method to
// perform host key algorithm lookups from the known_hosts entries. It is
// otherwise identical to ssh.HostKeyCallback, and does not introduce any file-
// parsing behavior beyond what is in golang.org/x/crypto/ssh/knownhosts.
//
// Note that its HostKeys and HostKeyAlgorithms methods do not provide any
// special treatment for @cert-authority lines, which will look like normal
// non-CA host keys. For proper CA support, e.g. when building a general-purpose
// SSH client, use HostKeyDB instead.
//
// HostKeyCallback should generally only be used in situations in which
// @cert-authority lines are unlikely (for example, Git-related use-cases, since
// Git forges generally don't use them), or in situations where the extra file-
// parsing is undesirable, for reasons of code trust / security or perhaps
// performance impact.
type HostKeyCallback ssh.HostKeyCallback

// New creates a HostKeyCallback from the given OpenSSH known_hosts file(s). The
// returned value may be used in ssh.ClientConfig.HostKeyCallback by casting it
// to ssh.HostKeyCallback, or using its HostKeyCallback method. Otherwise, it
// operates the same as the New function in golang.org/x/crypto/ssh/knownhosts.
// When supplying multiple files, their order does not matter.
func New(files ...string) (HostKeyCallback, error) {
	cb, err := xknownhosts.New(files...)
	return HostKeyCallback(cb), err
}

// HostKeyCallback simply casts the receiver back to ssh.HostKeyCallback, for
// use in ssh.ClientConfig.HostKeyCallback.
func (hkcb HostKeyCallback) HostKeyCallback() ssh.HostKeyCallback {
	return ssh.HostKeyCallback(hkcb)
}

// HostKeys returns a slice of known host public keys for the supplied host:port
// found in the known_hosts file(s), or an empty slice if the host is not
// already known. For hosts that have multiple known_hosts entries (for
// different key types), the result will be sorted by known_hosts filename and
// line number.
// In the returned values, there is no way to distinguish between CA keys
// (known_hosts lines beginning with @cert-authority) and regular keys. To do so,
// use HostKeyDB.HostKeys instead.
func (hkcb HostKeyCallback) HostKeys(hostWithPort string) []ssh.PublicKey {
	// Approach: create a HostKeyDB without an isCert map; call its HostKeys
	// method (which will skip the cert-related logic due to isCert map being
	// nil); pull out the ssh.PublicKey from each result
	hkdb := HostKeyDB{callback: ssh.HostKeyCallback(hkcb)}
	annotatedKeys := hkdb.HostKeys(hostWithPort)
	rawKeys := make([]ssh.PublicKey, len(annotatedKeys))
	for n, ak := range annotatedKeys {
		rawKeys[n] = ak.PublicKey
	}
	return rawKeys
}

// HostKeyAlgorithms returns a slice of host key algorithms for the supplied
// host:port found in the known_hosts file(s), or an empty slice if the host
// is not already known. The result may be used in ssh.ClientConfig's
// HostKeyAlgorithms field, either as-is or after filtering (if you wish to
// ignore or prefer particular algorithms). For hosts that have multiple
// known_hosts entries (for different key types), the result will be sorted by
// known_hosts filename and line number.
// The returned values will not include ssh.CertAlgo* values. If any
// known_hosts lines had @cert-authority prefixes, their original key algo will
// be returned instead. For proper CA support, use HostKeyDB.HostKeyAlgorithms.
func (hkcb HostKeyCallback) HostKeyAlgorithms(hostWithPort string) (algos []string) {
	// Approach: create a HostKeyDB without an isCert map; call its
	// HostKeyAlgorithms method (which will skip the cert-related logic due to
	// isCert map being nil); the result is suitable for returning as-is
	hkdb := HostKeyDB{callback: ssh.HostKeyCallback(hkcb)}
	return hkdb.HostKeyAlgorithms(hostWithPort)
}

// HostKeyAlgorithms is a convenience function for performing host key algorithm
// lookups on an ssh.HostKeyCallback directly. It is intended for use in code
// paths that stay with the New method of golang.org/x/crypto/ssh/knownhosts
// rather than this package's New or NewDB methods.
// The returned values will not include ssh.CertAlgo* values. If any
// known_hosts lines had @cert-authority prefixes, their original key algo will
// be returned instead. For proper CA support, use HostKeyDB.HostKeyAlgorithms.
func HostKeyAlgorithms(cb ssh.HostKeyCallback, hostWithPort string) []string {
	return HostKeyCallback(cb).HostKeyAlgorithms(hostWithPort)
}

// IsHostKeyChanged returns a boolean indicating whether the error indicates
// the host key has changed. It is intended to be called on the error returned
// from invoking a host key callback, to check whether an SSH host is known.
func IsHostKeyChanged(err error) bool {
	var keyErr *xknownhosts.KeyError
	return errors.As(err, &keyErr) && len(keyErr.Want) > 0
}

// IsHostUnknown returns a boolean indicating whether the error represents an
// unknown host. It is intended to be called on the error returned from invoking
// a host key callback to check whether an SSH host is known.
func IsHostUnknown(err error) bool {
	var keyErr *xknownhosts.KeyError
	return errors.As(err, &keyErr) && len(keyErr.Want) == 0
}

// Normalize normalizes an address into the form used in known_hosts. This
// implementation includes a fix for https://github.com/golang/go/issues/53463
// and will omit brackets around ipv6 addresses on standard port 22.
func Normalize(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host = address
		port = "22"
	}
	entry := host
	if port != "22" {
		entry = "[" + entry + "]:" + port
	} else if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		entry = entry[1 : len(entry)-1]
	}
	return entry
}

// Line returns a line to append to the known_hosts files. This implementation
// uses the local patched implementation of Normalize in order to solve
// https://github.com/golang/go/issues/53463.
func Line(addresses []string, key ssh.PublicKey) string {
	var trimmed []string
	for _, a := range addresses {
		trimmed = append(trimmed, Normalize(a))
	}

	return strings.Join([]string{
		strings.Join(trimmed, ","),
		key.Type(),
		base64.StdEncoding.EncodeToString(key.Marshal()),
	}, " ")
}

// WriteKnownHost writes a known_hosts line to writer for the supplied hostname,
// remote, and key. This is useful when writing a custom hostkey callback which
// wraps a callback obtained from this package to provide additional known_hosts
// management functionality. The hostname, remote, and key typically correspond
// to the callback's args. This function does not support writing
// @cert-authority lines.
func WriteKnownHost(w io.Writer, hostname string, remote net.Addr, key ssh.PublicKey) error {
	// Always include hostname; only also include remote if it isn't a zero value
	// and doesn't normalize to the same string as hostname.
	hostnameNormalized := Normalize(hostname)
	if strings.ContainsAny(hostnameNormalized, "\t ") {
		return fmt.Errorf("knownhosts: hostname '%s' contains spaces", hostnameNormalized)
	}
	addresses := []string{hostnameNormalized}
	remoteStrNormalized := Normalize(remote.String())
	if remoteStrNormalized != "[0.0.0.0]:0" && remoteStrNormalized != hostnameNormalized &&
		!strings.ContainsAny(remoteStrNormalized, "\t ") {
		addresses = append(addresses, remoteStrNormalized)
	}
	line := Line(addresses, key) + "\n"
	_, err := w.Write([]byte(line))
	return err
}

// fakePublicKey is used as part of the work-around for
// https://github.com/golang/go/issues/29286
type fakePublicKey struct{}

func (fakePublicKey) Type() string {
	return "fake-public-key"
}
func (fakePublicKey) Marshal() []byte {
	return []byte("fake public key")
}
func (fakePublicKey) Verify(_ []byte, _ *ssh.Signature) error {
	return errors.New("Verify called on placeholder key")
}
