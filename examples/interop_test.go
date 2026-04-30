package main

import (
	"crypto/rand"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
	tob "github.com/trailofbits/go-slh-dsa/slh_dsa"
)

// TestInterop_SHA2_128s cross-tests SLH-DSA-SHA2-128s between Cloudflare CIRCL
// and Trail of Bits go-slh-dsa implementations.
func TestInterop_SHA2_128s(t *testing.T) {
	msg := []byte("test message for interop")
	ctx := []byte{}
	params := tob.SlhDsaSha2_128s()

	circlPub, circlPriv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)
	if err != nil {
		t.Fatalf("CIRCL GenerateKey: %v", err)
	}
	pubBytes, _ := circlPub.MarshalBinary()
	privBytes, _ := circlPriv.MarshalBinary()

	tobPub, err := tob.LoadPublicKey(params, pubBytes)
	if err != nil {
		t.Fatalf("ToB LoadPublicKey: %v", err)
	}
	tobPriv, err := tob.LoadSecretKey(params, privBytes)
	if err != nil {
		t.Fatalf("ToB LoadSecretKey: %v", err)
	}

	t.Run("CIRCL_sign_ToB_verify", func(t *testing.T) {
		sig, err := slhdsa.SignDeterministic(&circlPriv, slhdsa.NewMessage(msg), ctx)
		if err != nil {
			t.Fatalf("CIRCL Sign: %v", err)
		}
		tobSig, err := tob.LoadSignature(params, sig)
		if err != nil {
			t.Fatalf("ToB LoadSignature: %v", err)
		}
		if !tobPub.Verify(tobSig, msg, ctx) {
			t.Fatal("Trail of Bits failed to verify CIRCL signature")
		}
		t.Logf("OK: sig %d bytes", len(sig))
	})

	t.Run("ToB_sign_CIRCL_verify", func(t *testing.T) {
		sigBytes, err := tobPriv.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatalf("ToB Sign: %v", err)
		}
		if !slhdsa.Verify(&circlPub, slhdsa.NewMessage(msg), sigBytes, ctx) {
			t.Fatal("CIRCL failed to verify Trail of Bits signature")
		}
		t.Logf("OK: sig %d bytes", len(sigBytes))
	})

	t.Run("key_roundtrip", func(t *testing.T) {
		assertBytesEqual(t, pubBytes, tobPub.Bytes(), "public key")
		assertBytesEqual(t, privBytes, tobPriv.Bytes(), "private key")
	})
}

// TestInterop_SHAKE_128s cross-tests SLH-DSA-SHAKE-128s.
func TestInterop_SHAKE_128s(t *testing.T) {
	msg := []byte("test message for interop")
	ctx := []byte{}
	params := tob.SlhDsaShake_128s()

	circlPub, circlPriv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_128s)
	if err != nil {
		t.Fatalf("CIRCL GenerateKey: %v", err)
	}
	pubBytes, _ := circlPub.MarshalBinary()
	privBytes, _ := circlPriv.MarshalBinary()

	tobPub, err := tob.LoadPublicKey(params, pubBytes)
	if err != nil {
		t.Fatalf("ToB LoadPublicKey: %v", err)
	}
	tobPriv, err := tob.LoadSecretKey(params, privBytes)
	if err != nil {
		t.Fatalf("ToB LoadSecretKey: %v", err)
	}

	t.Run("CIRCL_sign_ToB_verify", func(t *testing.T) {
		sig, err := slhdsa.SignDeterministic(&circlPriv, slhdsa.NewMessage(msg), ctx)
		if err != nil {
			t.Fatalf("CIRCL Sign: %v", err)
		}
		tobSig, err := tob.LoadSignature(params, sig)
		if err != nil {
			t.Fatalf("ToB LoadSignature: %v", err)
		}
		if !tobPub.Verify(tobSig, msg, ctx) {
			t.Fatal("Trail of Bits failed to verify CIRCL signature")
		}
		t.Logf("OK: sig %d bytes", len(sig))
	})

	t.Run("ToB_sign_CIRCL_verify", func(t *testing.T) {
		sigBytes, err := tobPriv.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatalf("ToB Sign: %v", err)
		}
		if !slhdsa.Verify(&circlPub, slhdsa.NewMessage(msg), sigBytes, ctx) {
			t.Fatal("CIRCL failed to verify Trail of Bits signature")
		}
		t.Logf("OK: sig %d bytes", len(sigBytes))
	})

	t.Run("key_roundtrip", func(t *testing.T) {
		assertBytesEqual(t, pubBytes, tobPub.Bytes(), "public key")
		assertBytesEqual(t, privBytes, tobPriv.Bytes(), "private key")
	})
}

// TestInterop_SHA2_128f cross-tests SLH-DSA-SHA2-128f.
func TestInterop_SHA2_128f(t *testing.T) {
	msg := []byte("test message for interop")
	ctx := []byte{}
	params := tob.SlhDsaSha2_128f()

	circlPub, circlPriv, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)
	if err != nil {
		t.Fatalf("CIRCL GenerateKey: %v", err)
	}
	pubBytes, _ := circlPub.MarshalBinary()
	privBytes, _ := circlPriv.MarshalBinary()

	tobPub, err := tob.LoadPublicKey(params, pubBytes)
	if err != nil {
		t.Fatalf("ToB LoadPublicKey: %v", err)
	}
	tobPriv, err := tob.LoadSecretKey(params, privBytes)
	if err != nil {
		t.Fatalf("ToB LoadSecretKey: %v", err)
	}

	t.Run("CIRCL_sign_ToB_verify", func(t *testing.T) {
		sig, err := slhdsa.SignDeterministic(&circlPriv, slhdsa.NewMessage(msg), ctx)
		if err != nil {
			t.Fatalf("CIRCL Sign: %v", err)
		}
		tobSig, err := tob.LoadSignature(params, sig)
		if err != nil {
			t.Fatalf("ToB LoadSignature: %v", err)
		}
		if !tobPub.Verify(tobSig, msg, ctx) {
			t.Fatal("Trail of Bits failed to verify CIRCL signature")
		}
		t.Logf("OK: sig %d bytes", len(sig))
	})

	t.Run("ToB_sign_CIRCL_verify", func(t *testing.T) {
		sigBytes, err := tobPriv.Sign(rand.Reader, msg, nil)
		if err != nil {
			t.Fatalf("ToB Sign: %v", err)
		}
		if !slhdsa.Verify(&circlPub, slhdsa.NewMessage(msg), sigBytes, ctx) {
			t.Fatal("CIRCL failed to verify Trail of Bits signature")
		}
		t.Logf("OK: sig %d bytes", len(sigBytes))
	})

	t.Run("key_roundtrip", func(t *testing.T) {
		assertBytesEqual(t, pubBytes, tobPub.Bytes(), "public key")
		assertBytesEqual(t, privBytes, tobPriv.Bytes(), "private key")
	})
}

func assertBytesEqual(t *testing.T, a, b []byte, label string) {
	t.Helper()
	if len(a) != len(b) {
		t.Fatalf("%s length mismatch: %d vs %d", label, len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("%s byte mismatch at index %d", label, i)
		}
	}
}
