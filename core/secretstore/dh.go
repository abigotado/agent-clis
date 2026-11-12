package secretstore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
)

// This file is the Secret Service session algorithm
// dh-ietf1024-sha256-aes128-cbc-pkcs7. It is untagged and uses only the
// standard library, so its vectors run on every platform. It only keeps a
// passive observer of the session bus from reading a secret in transit; code
// of the same user can call GetSecret itself, so it is hygiene and not a
// boundary.
//
// The key exchange is Diffie-Hellman in the 1024-bit MODP group of RFC 2409
// section 6.2 (Oakley group 2, generator 2). Public values and the shared
// secret are 128-byte big-endian integers with their leading zeros kept. The
// AES key is HKDF-SHA256 over the shared secret with a NULL salt (HashLen
// zero bytes, RFC 5869) and empty info, truncated to 16 bytes.

const (
	// dhAlgorithm is the algorithm name passed to OpenSession.
	dhAlgorithm = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
	// dhValueBytes is the size of a public value and of the shared secret.
	dhValueBytes = 128
	// dhKeyBytes is the AES-128 key size HKDF produces.
	dhKeyBytes = 16
)

// dhPrimeHex is the prime of RFC 2409 Oakley group 2:
// 2^1024 - 2^960 - 1 + 2^64 * { [2^894 pi] + 129093 }.
const dhPrimeHex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
	"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
	"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
	"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
	"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381" +
	"FFFFFFFFFFFFFFFF"

// errDHPeer is returned for a server public value, or a shared secret, that
// is outside the safe range or malformed.
var errDHPeer = errors.New("secretstore: invalid key exchange value")

// errDHCipher is the one error every decryption failure returns, whatever the
// cause (length, padding), so the failure does not tell an observer which check
// failed.
var errDHCipher = errors.New("secretstore: invalid ciphertext")

// dhPrime returns a fresh copy of the group prime, so no shared big.Int can be
// mutated by accident.
func dhPrime() *big.Int {
	p, ok := new(big.Int).SetString(dhPrimeHex, 16)
	if !ok {
		panic("secretstore: malformed built-in DH prime") // a constant; never reached
	}
	return p
}

// dhKeyPair is one side of an exchange.
type dhKeyPair struct {
	priv *big.Int
	pub  []byte // dhValueBytes, big-endian
}

// newDHKeyPair draws a private exponent uniformly from [2, p-2] and computes
// 2^x mod p.
func newDHKeyPair(random io.Reader) (*dhKeyPair, error) {
	p := dhPrime()
	span := new(big.Int).Sub(p, big.NewInt(3)) // x-2 in [0, p-4]
	n, err := rand.Int(random, span)
	if err != nil {
		return nil, errors.New("secretstore: draw a key exchange exponent")
	}
	priv := n.Add(n, big.NewInt(2))
	pub := new(big.Int).Exp(big.NewInt(2), priv, p)
	k := &dhKeyPair{priv: priv, pub: make([]byte, dhValueBytes)}
	pub.FillBytes(k.pub)
	return k, nil
}

// wipe zeroes the private exponent's words. The exponent has no other use once
// the key is derived. big.Int offers no guarantee about intermediate values
// that Exp left behind, so this is best effort.
func (k *dhKeyPair) wipe() {
	clear(k.priv.Bits())
}

// newDHKeyPairFromExponent builds a pair from a known exponent, for vectors.
func newDHKeyPairFromExponent(priv *big.Int) *dhKeyPair {
	p := dhPrime()
	k := &dhKeyPair{priv: new(big.Int).Set(priv), pub: make([]byte, dhValueBytes)}
	new(big.Int).Exp(big.NewInt(2), priv, p).FillBytes(k.pub)
	return k
}

// deriveKey validates the peer's public value and returns the 16-byte AES key.
// The peer value y must satisfy 1 < y < p-1 and fit in 128 bytes (leading
// zeros may be absent); the shared secret must be neither 1 nor p-1.
func (k *dhKeyPair) deriveKey(peer []byte) ([]byte, error) {
	if len(peer) == 0 || len(peer) > dhValueBytes {
		return nil, errDHPeer
	}
	p := dhPrime()
	one := big.NewInt(1)
	pMinusOne := new(big.Int).Sub(p, one)
	y := new(big.Int).SetBytes(peer)
	if y.Cmp(one) <= 0 || y.Cmp(pMinusOne) >= 0 {
		return nil, errDHPeer
	}
	z := new(big.Int).Exp(y, k.priv, p)
	if z.Cmp(one) == 0 || z.Cmp(pMinusOne) == 0 {
		return nil, errDHPeer
	}
	shared := make([]byte, dhValueBytes)
	z.FillBytes(shared)
	defer clear(shared)
	defer clear(z.Bits())
	key, err := hkdf.Key(sha256.New, shared, nil, "", dhKeyBytes)
	if err != nil {
		return nil, errDHPeer
	}
	return key, nil
}

// dhEncrypt pads plaintext with PKCS#7 and encrypts it with AES-128-CBC under
// a random IV. The caller's slice is not modified; the padded copy is wiped.
func dhEncrypt(key, plaintext []byte, random io.Reader) (iv, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, errDHCipher
	}
	pad := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := make([]byte, len(plaintext)+pad)
	defer clear(padded)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	iv = make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(random, iv); err != nil {
		return nil, nil, errors.New("secretstore: draw an initialization vector")
	}
	ciphertext = make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return iv, ciphertext, nil
}

// dhDecrypt decrypts ciphertext and removes the PKCS#7 padding. Every failure,
// a wrong IV or ciphertext length or bad padding, returns errDHCipher, and
// the padding is checked without branching on its content. The returned
// plaintext is a fresh slice the caller zeroes; ciphertext is left as it is.
func dhDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil || len(iv) != aes.BlockSize ||
		len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errDHCipher
	}
	padded := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(padded, ciphertext)
	n := len(padded)
	pad := int(padded[n-1])
	valid := subtle.ConstantTimeLessOrEq(1, pad) & subtle.ConstantTimeLessOrEq(pad, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		inPad := subtle.ConstantTimeLessOrEq(i+1, pad)
		same := subtle.ConstantTimeByteEq(padded[n-1-i], byte(pad))
		valid &= (1 ^ inPad) | same
	}
	if valid != 1 {
		clear(padded)
		return nil, errDHCipher
	}
	plain := make([]byte, n-pad)
	copy(plain, padded)
	clear(padded)
	return plain, nil
}
