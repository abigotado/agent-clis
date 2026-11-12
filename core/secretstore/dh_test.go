package secretstore

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in test: %v", err)
	}
	return b
}

func hexExponent(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("bad exponent %q", s)
	}
	return n
}

// fixedReader serves bytes from a fixed buffer, then fails.
type fixedReader struct{ buf []byte }

func (r *fixedReader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		return 0, errors.New("fixed reader exhausted")
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// TestDHPrime checks the built-in constant against the properties RFC 2409
// gives it: 1024 bits, prime, and a safe prime ((p-1)/2 is prime too).
func TestDHPrime(t *testing.T) {
	p := dhPrime()
	if p.BitLen() != 1024 {
		t.Fatalf("prime has %d bits, want 1024", p.BitLen())
	}
	if !p.ProbablyPrime(20) {
		t.Fatal("the group modulus is not prime")
	}
	q := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	if !q.ProbablyPrime(20) {
		t.Fatal("the group modulus is not a safe prime")
	}
	if got := dhPrime(); got == p {
		t.Fatal("dhPrime returned a shared big.Int")
	}
}

// The vectors below were computed outside this code base: the exponentiation
// with Python integers, HKDF-SHA256 with a hand-written HMAC construction, and
// AES-128-CBC with the openssl command.
func TestDHVectors(t *testing.T) {
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	tests := []struct {
		name               string
		clientExp, srvExp  string
		pubClient, pubSrv  string
		sharedPrefix       string
		key                string
		plaintext, cipherH string
	}{
		{
			name:      "typical",
			clientExp: "24197857200151252728969465429440056815",
			srvExp:    "338769989521388930494245921488005055265",
			pubClient: "7918d89680ab92ce7e10792825847ec546310372ad685a1899dc3b12381cb197ea4b7a89984b17a85ac9bb6b1dca6038d61d275557c86f5615b55cde6b07777c8326cef8290146ccb05c67539a3fd6ad0374f8b864283e4a9617482df646a33ce6f5e1453c5c5a012576f43886d47d6f272508da24ca059907b8db9f288b4e3c",
			pubSrv:    "a49e9861bc70128ad73c00744f1a57162275939d9b10479c65510b2fd00e423dda598d341906f21c98535be518dd6f589f3a613aeaada094c7be7464fce38f26ac1acf4058ac2e7ae09c3593af1ffee8e085a1fa26f49f83afd529048e6d418abd12155718227767bfac45c71de1b09d88b2fe2e057f4bccdaa65d676a097cdf",
			key:       "553f0fd1cbaa75b81f9e2458702a347c",
			plaintext: "correct horse battery staple",
			cipherH:   "f4ad535ce03adc32635c74366229f753f1a1166c25d23cdc7d755d0c5f3d4732",
		},
		{
			// The shared secret starts with a zero byte, so a conversion that
			// drops leading zeros derives a different key.
			name:      "shared secret with a leading zero byte",
			clientExp: "92",
			srvExp:    "338769989521388930494245921488005055265",
			pubClient: strings.Repeat("00", 116) + "10" + strings.Repeat("00", 11),
			pubSrv:    "a49e9861bc70128ad73c00744f1a57162275939d9b10479c65510b2fd00e423dda598d341906f21c98535be518dd6f589f3a613aeaada094c7be7464fce38f26ac1acf4058ac2e7ae09c3593af1ffee8e085a1fa26f49f83afd529048e6d418abd12155718227767bfac45c71de1b09d88b2fe2e057f4bccdaa65d676a097cdf",
			key:       "61023d1800880b90d40b5c59904f80bf",
			plaintext: "x",
			cipherH:   "50fa1e11c68bb47069873e9c5c9a5689",
		},
		{
			// Small public values, a shared secret with many leading zeros, and
			// a plaintext of exactly one block, which takes a whole padding block.
			name:      "short public values and a full block",
			clientExp: "7",
			srvExp:    "11",
			pubClient: strings.Repeat("00", 127) + "80",
			pubSrv:    strings.Repeat("00", 126) + "0800",
			key:       "312f7646dc9c055f6408e32f2d52a700",
			plaintext: "0123456789abcdef",
			cipherH:   "82688f7027a061059f55f91f0262d7ee75841a8ad253b784f954766a5d980f11",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newDHKeyPairFromExponent(hexExponent(t, tt.clientExp))
			server := newDHKeyPairFromExponent(hexExponent(t, tt.srvExp))
			if got := hex.EncodeToString(client.pub); got != tt.pubClient {
				t.Fatalf("client public value = %s, want %s", got, tt.pubClient)
			}
			if got := hex.EncodeToString(server.pub); got != tt.pubSrv {
				t.Fatalf("server public value = %s, want %s", got, tt.pubSrv)
			}
			key, err := client.deriveKey(server.pub)
			if err != nil {
				t.Fatalf("client deriveKey: %v", err)
			}
			if got := hex.EncodeToString(key); got != tt.key {
				t.Fatalf("client key = %s, want %s", got, tt.key)
			}
			serverKey, err := server.deriveKey(client.pub)
			if err != nil || !bytes.Equal(serverKey, key) {
				t.Fatalf("server key = %x, %v; want %x", serverKey, err, key)
			}

			plaintext := []byte(tt.plaintext)
			gotIV, ct, err := dhEncrypt(key, plaintext, &fixedReader{buf: iv})
			if err != nil {
				t.Fatalf("dhEncrypt: %v", err)
			}
			if !bytes.Equal(gotIV, iv) {
				t.Fatalf("iv = %x, want %x", gotIV, iv)
			}
			if got := hex.EncodeToString(ct); got != tt.cipherH {
				t.Fatalf("ciphertext = %s, want %s", got, tt.cipherH)
			}
			if string(plaintext) != tt.plaintext {
				t.Fatal("dhEncrypt modified its input")
			}
			got, err := dhDecrypt(key, iv, mustHex(t, tt.cipherH))
			if err != nil || string(got) != tt.plaintext {
				t.Fatalf("dhDecrypt = %q, %v; want %q", got, err, tt.plaintext)
			}
		})
	}
}

func TestDHDeriveKeyRejectsPeerValue(t *testing.T) {
	p := dhPrime()
	pMinusOne := new(big.Int).Sub(p, big.NewInt(1))
	pPlusOne := new(big.Int).Add(p, big.NewInt(1))
	be := func(n *big.Int) []byte { return n.FillBytes(make([]byte, dhValueBytes)) }
	tests := []struct {
		name string
		peer []byte
	}{
		{"empty", nil},
		{"zero", []byte{0}},
		{"zero full length", make([]byte, dhValueBytes)},
		{"one", []byte{1}},
		{"one full length", be(big.NewInt(1))},
		{"p minus one", be(pMinusOne)},
		{"p", be(p)},
		{"p plus one, too long", pPlusOne.Bytes()},
		{"longer than the group", append([]byte{1}, make([]byte, dhValueBytes)...)},
	}
	client := newDHKeyPairFromExponent(big.NewInt(12345))
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := client.deriveKey(tt.peer)
			if !errors.Is(err, errDHPeer) || key != nil {
				t.Fatalf("deriveKey = %x, %v; want errDHPeer", key, err)
			}
		})
	}
	t.Run("two is accepted", func(t *testing.T) {
		if _, err := client.deriveKey([]byte{2}); err != nil {
			t.Fatalf("deriveKey(2): %v", err)
		}
	})
	t.Run("p minus two is accepted", func(t *testing.T) {
		if _, err := client.deriveKey(be(new(big.Int).Sub(p, big.NewInt(2)))); err != nil {
			t.Fatalf("deriveKey(p-2): %v", err)
		}
	})
}

// With a safe prime p = 2q+1 the exponent q maps a quadratic residue to 1 and
// a non-residue to p-1, so a peer value inside 1 < y < p-1 can still produce a
// trivial shared secret. 4 is a residue; p-4 is a non-residue because -1 is.
func TestDHDeriveKeyRejectsTrivialSharedSecret(t *testing.T) {
	p := dhPrime()
	q := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	pair := newDHKeyPairFromExponent(q)
	tests := []struct {
		name string
		peer *big.Int
	}{
		{"shared secret 1", big.NewInt(4)},
		{"shared secret p-1", new(big.Int).Sub(p, big.NewInt(4))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := pair.deriveKey(tt.peer.FillBytes(make([]byte, dhValueBytes)))
			if !errors.Is(err, errDHPeer) || key != nil {
				t.Fatalf("deriveKey = %x, %v; want errDHPeer", key, err)
			}
		})
	}
}

func TestDHKeyPairExchangeAgrees(t *testing.T) {
	for range 4 {
		a, err := newDHKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("newDHKeyPair: %v", err)
		}
		b, err := newDHKeyPair(rand.Reader)
		if err != nil {
			t.Fatalf("newDHKeyPair: %v", err)
		}
		ka, err := a.deriveKey(b.pub)
		if err != nil {
			t.Fatalf("deriveKey: %v", err)
		}
		kb, err := b.deriveKey(a.pub)
		if err != nil || !bytes.Equal(ka, kb) || len(ka) != dhKeyBytes {
			t.Fatalf("keys differ or have the wrong size: %x %x %v", ka, kb, err)
		}
	}
}

func TestDHNewKeyPairReportsRandomFailure(t *testing.T) {
	if _, err := newDHKeyPair(&fixedReader{}); err == nil {
		t.Fatal("newDHKeyPair succeeded without randomness")
	}
}

func TestDHEncryptReportsRandomFailure(t *testing.T) {
	if _, _, err := dhEncrypt(make([]byte, dhKeyBytes), []byte("x"), &fixedReader{}); err == nil {
		t.Fatal("dhEncrypt succeeded without an IV")
	}
}

func TestDHDecryptFailuresAreOneError(t *testing.T) {
	key := mustHex(t, "553f0fd1cbaa75b81f9e2458702a347c")
	iv := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	_, goodCT, err := dhEncrypt(key, []byte("hello"), &fixedReader{buf: iv})
	if err != nil {
		t.Fatalf("dhEncrypt: %v", err)
	}
	// forge builds a ciphertext whose plaintext is the given padded bytes.
	forge := func(padded []byte) []byte {
		block, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("forge: %v", err)
		}
		ct := make([]byte, len(padded))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
		return ct
	}
	block := func(last byte, fill byte, padLen int) []byte {
		b := bytes.Repeat([]byte{'A'}, 16)
		for i := 16 - padLen; i < 16; i++ {
			b[i] = fill
		}
		b[15] = last
		return b
	}
	tests := []struct {
		name string
		iv   []byte
		ct   []byte
	}{
		{"empty ciphertext", iv, nil},
		{"short ciphertext", iv, goodCT[:15]},
		{"unaligned ciphertext", iv, append(bytes.Clone(goodCT), 0)},
		{"short IV", iv[:15], goodCT},
		{"long IV", append(bytes.Clone(iv), 0), goodCT},
		{"no IV", nil, goodCT},
		{"pad byte zero", iv, forge(block(0, 0, 1))},
		{"pad byte above block size", iv, forge(block(17, 17, 1))},
		{"pad byte 0xff", iv, forge(block(0xff, 0xff, 1))},
		{"pad bytes disagree", iv, forge(block(4, 3, 3))},
		{"only the last pad byte matches", iv, forge(block(4, 9, 4))},
		{"pad bytes shorter than claimed", iv, forge(append(bytes.Repeat([]byte{'A'}, 15), 2))},
		{"garbled ciphertext block", iv, func() []byte { c := bytes.Clone(goodCT); c[15] ^= 0x5a; return c }()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := dhDecrypt(key, tt.iv, tt.ct)
			if err != errDHCipher || got != nil {
				t.Fatalf("dhDecrypt = %q, %v; want errDHCipher", got, err)
			}
		})
	}
	t.Run("a full padding block is accepted", func(t *testing.T) {
		got, err := dhDecrypt(key, iv, forge(bytes.Repeat([]byte{16}, 16)))
		if err != nil || len(got) != 0 {
			t.Fatalf("dhDecrypt = %q, %v; want empty plaintext", got, err)
		}
	})
}

func TestDHKeyPairWipeZeroesTheExponent(t *testing.T) {
	pair, err := newDHKeyPair(rand.Reader)
	if err != nil {
		t.Fatalf("newDHKeyPair: %v", err)
	}
	words := pair.priv.Bits()
	if len(words) == 0 {
		t.Fatal("a fresh exponent has no words, so the test could not tell a wipe from nothing")
	}
	pair.wipe()
	for i, w := range words {
		if w != 0 {
			t.Fatalf("exponent word %d is %#x after wipe", i, w)
		}
	}
}
