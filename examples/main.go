// Program to generate SLH-DSA test vectors for JOSE and COSE serializations.
//
// Cross-validates key material between Cloudflare CIRCL and Trail of Bits
// go-slh-dsa implementations before generating test vectors for the
// draft-ietf-cose-sphincs-plus specification.
//
// Reproducibility: Key generation uses a deterministic PRNG seeded from the
// constant vectorSeed (AES-CTR with SHA-256 derived key). Signing uses CIRCL's
// SignDeterministic. Running this program with the same seed and the same
// library versions will always produce identical test vectors.
//
// Test vectors are written to ../testvectors/ in formats suitable for
// inclusion via kramdown-rfc {::include} directives.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/fxamacker/cbor/v2"
	tob "github.com/trailofbits/go-slh-dsa/slh_dsa"
)

// vectorSeed is the fixed seed used to derive deterministic key material.
// Changing this value will produce different test vectors.
const vectorSeed = "draft-ietf-cose-sphincs-plus test vectors v1"

// deterministicRand returns a deterministic io.Reader for the given algorithm
// name. Each algorithm gets its own independent byte stream derived from
// SHA-256(vectorSeed + ":" + algName), used as an AES-CTR key with a zero IV.
// This ensures test vector generation is fully reproducible.
func deterministicRand(algName string) io.Reader {
	seed := sha256.Sum256([]byte(vectorSeed + ":" + algName))
	block, err := aes.NewCipher(seed[:])
	if err != nil {
		fatalf("aes.NewCipher: %v", err)
	}
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	return &cipher.StreamReader{S: stream, R: zeroReader{}}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func main() {
	outDir := filepath.Join("..", "testvectors")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fatalf("mkdir testvectors: %v", err)
	}

	fmt.Printf("Seed: %q\n", vectorSeed)
	genSHA2_128s(outDir)
	genSHAKE_128s(outDir)
	genSHA2_128f(outDir)

	fmt.Println("Done.")
}

func genSHA2_128s(outDir string) {
	name := "SLH-DSA-SHA2-128s"
	var coseAlg int64 = -51
	fmt.Printf("Generating test vectors for %s ...\n", name)
	dir := filepath.Join(outDir, name)
	os.MkdirAll(dir, 0o755)

	circlPub, circlPriv, err := slhdsa.GenerateKey(deterministicRand(name), slhdsa.SHA2_128s)
	if err != nil {
		fatalf("GenerateKey: %v", err)
	}
	pubBytes, _ := circlPub.MarshalBinary()
	privBytes, _ := circlPriv.MarshalBinary()

	// Cross-validate with Trail of Bits
	params := tob.SlhDsaSha2_128s()
	crossValidate(name, params, pubBytes, privBytes, &circlPub, &circlPriv)

	kid := "slh-dsa-sha2-128s-kid"
	payload := []byte("fake")

	generateJOSE(name, dir, pubBytes, privBytes, payload, kid, &circlPriv)
	generateCOSE(name, coseAlg, dir, pubBytes, privBytes, payload, kid, &circlPriv, params)
	fmt.Printf("  Test vectors written to %s\n", dir)
}

func genSHAKE_128s(outDir string) {
	name := "SLH-DSA-SHAKE-128s"
	var coseAlg int64 = -52
	fmt.Printf("Generating test vectors for %s ...\n", name)
	dir := filepath.Join(outDir, name)
	os.MkdirAll(dir, 0o755)

	circlPub, circlPriv, err := slhdsa.GenerateKey(deterministicRand(name), slhdsa.SHAKE_128s)
	if err != nil {
		fatalf("GenerateKey: %v", err)
	}
	pubBytes, _ := circlPub.MarshalBinary()
	privBytes, _ := circlPriv.MarshalBinary()

	params := tob.SlhDsaShake_128s()
	crossValidate(name, params, pubBytes, privBytes, &circlPub, &circlPriv)

	kid := "slh-dsa-shake-128s-kid"
	payload := []byte("fake")

	generateJOSE(name, dir, pubBytes, privBytes, payload, kid, &circlPriv)
	generateCOSE(name, coseAlg, dir, pubBytes, privBytes, payload, kid, &circlPriv, params)
	fmt.Printf("  Test vectors written to %s\n", dir)
}

func genSHA2_128f(outDir string) {
	name := "SLH-DSA-SHA2-128f"
	var coseAlg int64 = -53
	fmt.Printf("Generating test vectors for %s ...\n", name)
	dir := filepath.Join(outDir, name)
	os.MkdirAll(dir, 0o755)

	circlPub, circlPriv, err := slhdsa.GenerateKey(deterministicRand(name), slhdsa.SHA2_128f)
	if err != nil {
		fatalf("GenerateKey: %v", err)
	}
	pubBytes, _ := circlPub.MarshalBinary()
	privBytes, _ := circlPriv.MarshalBinary()

	params := tob.SlhDsaSha2_128f()
	crossValidate(name, params, pubBytes, privBytes, &circlPub, &circlPriv)

	kid := "slh-dsa-sha2-128f-kid"
	payload := []byte("fake")

	generateJOSE(name, dir, pubBytes, privBytes, payload, kid, &circlPriv)
	generateCOSE(name, coseAlg, dir, pubBytes, privBytes, payload, kid, &circlPriv, params)
	fmt.Printf("  Test vectors written to %s\n", dir)
}

func crossValidate(name string, tobParams interface{}, pubBytes, privBytes []byte,
	circlPub *slhdsa.PublicKey, circlPriv *slhdsa.PrivateKey) {
	// We use a type switch to handle the internal.ParamSet opaquely
	msg := []byte("cross-validation test")
	ctx := []byte{}

	// Sign with CIRCL
	sig, err := slhdsa.SignDeterministic(circlPriv, slhdsa.NewMessage(msg), ctx)
	if err != nil {
		fatalf("crossValidate Sign: %v", err)
	}

	// Verify the signature using Trail of Bits by calling the package-level function
	ok := tob.SLHVerify(msg, mustLoadSigByName(name, sig), ctx, mustLoadPubByName(name, pubBytes))
	if !ok {
		fatalf("Cross-validation failed: Trail of Bits could not verify CIRCL signature for %s", name)
	}
	fmt.Printf("  Cross-validated: CIRCL -> Trail of Bits (%d byte sig)\n", len(sig))
}

func mustLoadPubByName(name string, pubBytes []byte) tob.PublicKey {
	var pk tob.PublicKey
	var err error
	switch name {
	case "SLH-DSA-SHA2-128s":
		pk, err = tob.LoadPublicKey(tob.SlhDsaSha2_128s(), pubBytes)
	case "SLH-DSA-SHAKE-128s":
		pk, err = tob.LoadPublicKey(tob.SlhDsaShake_128s(), pubBytes)
	case "SLH-DSA-SHA2-128f":
		pk, err = tob.LoadPublicKey(tob.SlhDsaSha2_128f(), pubBytes)
	default:
		fatalf("unknown algorithm: %s", name)
	}
	if err != nil {
		fatalf("LoadPublicKey(%s): %v", name, err)
	}
	return pk
}

func mustLoadSigByName(name string, sigBytes []byte) tob.Signature {
	var s tob.Signature
	var err error
	switch name {
	case "SLH-DSA-SHA2-128s":
		s, err = tob.LoadSignature(tob.SlhDsaSha2_128s(), sigBytes)
	case "SLH-DSA-SHAKE-128s":
		s, err = tob.LoadSignature(tob.SlhDsaShake_128s(), sigBytes)
	case "SLH-DSA-SHA2-128f":
		s, err = tob.LoadSignature(tob.SlhDsaSha2_128f(), sigBytes)
	default:
		fatalf("unknown algorithm: %s", name)
	}
	if err != nil {
		fatalf("LoadSignature(%s): %v", name, err)
	}
	return s
}

func generateJOSE(algName, dir string, pubBytes, privBytes, payload []byte,
	kid string, circlPriv *slhdsa.PrivateKey) {
	b64url := base64.RawURLEncoding.EncodeToString

	// Private JWK
	privJWK := map[string]string{
		"kty":  "AKP",
		"alg":  algName,
		"kid":  kid,
		"pub":  b64url(pubBytes),
		"priv": b64url(privBytes),
	}
	writeJSON(filepath.Join(dir, "private-jwk.json"), privJWK)

	// Public JWK
	pubJWK := map[string]string{
		"kty": "AKP",
		"alg": algName,
		"kid": kid,
		"pub": b64url(pubBytes),
	}
	writeJSON(filepath.Join(dir, "public-jwk.json"), pubJWK)

	// JWS Compact Serialization
	header := map[string]string{
		"alg": algName,
		"kid": kid,
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := b64url(headerJSON)
	payloadB64 := b64url(payload)
	signingInput := headerB64 + "." + payloadB64

	msg := slhdsa.NewMessage([]byte(signingInput))
	jwsSig, err := slhdsa.SignDeterministic(circlPriv, msg, []byte{})
	if err != nil {
		fatalf("JWS Sign: %v", err)
	}
	sigB64 := b64url(jwsSig)
	jws := headerB64 + "." + payloadB64 + "." + sigB64
	writeFile(filepath.Join(dir, "jws.txt"), jws)
}

func generateCOSE(algName string, coseAlg int64, dir string,
	pubBytes, privBytes, payload []byte, kid string,
	circlPriv *slhdsa.PrivateKey, tobParams interface{}) {

	kidBytes := []byte(kid)

	// COSE Key diagnostic notation
	coseKeyDiag := formatCOSEKeyDiag(algName, coseAlg, pubBytes, privBytes, kidBytes)
	writeFile(filepath.Join(dir, "cose-key.diag"), coseKeyDiag)

	// Build COSE_Sign1
	protectedMap := map[int64]int64{1: coseAlg}
	protectedBytes, err := cbor.Marshal(protectedMap)
	if err != nil {
		fatalf("CBOR marshal protected: %v", err)
	}

	// Sig_structure = ["Signature1", protected, external_aad, payload]
	sigStructure := []interface{}{
		"Signature1",
		protectedBytes,
		[]byte{},
		payload,
	}
	sigInput, err := cbor.Marshal(sigStructure)
	if err != nil {
		fatalf("CBOR marshal Sig_structure: %v", err)
	}

	msg := slhdsa.NewMessage(sigInput)
	coseSig, err := slhdsa.SignDeterministic(circlPriv, msg, []byte{})
	if err != nil {
		fatalf("COSE Sign: %v", err)
	}

	// Cross-verify COSE signature with Trail of Bits
	tobPub := mustLoadPubByName(algName, pubBytes)
	tobSig := mustLoadSigByName(algName, coseSig)
	if !tobPub.Verify(tobSig, sigInput, []byte{}) {
		fatalf("COSE Sign1 cross-verify failed for %s", algName)
	}
	fmt.Printf("  COSE Sign1 cross-verified with Trail of Bits\n")

	// COSE Sign1 diagnostic notation
	sign1Diag := formatCOSESign1Diag(algName, coseAlg, payload, coseSig)
	writeFile(filepath.Join(dir, "cose-sign1.diag"), sign1Diag)

	// Raw CBOR binary
	sign1CBOR := buildCOSESign1CBOR(protectedBytes, payload, coseSig)
	writeFileBytes(filepath.Join(dir, "cose-sign1.cbor"), sign1CBOR)

	coseKeyCBOR := buildCOSEKeyCBOR(coseAlg, pubBytes, privBytes, kidBytes)
	writeFileBytes(filepath.Join(dir, "cose-key.cbor"), coseKeyCBOR)
}

func formatCOSEKeyDiag(algName string, coseAlg int64, pubBytes, privBytes, kidBytes []byte) string {
	var b strings.Builder
	b.WriteString("{\n")
	fmt.Fprintf(&b, "  / kty AKP                / 1: 7,\n")
	fmt.Fprintf(&b, "  / alg %-19s/ 3: %d,\n", algName+" ", coseAlg)
	fmt.Fprintf(&b, "  / kid                    / 2: h'%s',\n", hex.EncodeToString(kidBytes))
	fmt.Fprintf(&b, "  / public key             / -1:\n")
	b.WriteString(formatHexBlock(pubBytes, 0))
	fmt.Fprintf(&b, "  / private key            / -2:\n")
	b.WriteString(formatHexBlock(privBytes, 0))
	b.WriteString("}")
	return b.String()
}

func formatCOSESign1Diag(algName string, coseAlg int64, payload, sig []byte) string {
	var b strings.Builder
	b.WriteString("18([\n")
	fmt.Fprintf(&b, "  <<{\n")
	fmt.Fprintf(&b, "    / alg %s / 1: %d,\n", algName, coseAlg)
	fmt.Fprintf(&b, "  }>>,\n")
	fmt.Fprintf(&b, "  / unprotected / {},\n")
	fmt.Fprintf(&b, "  / payload / h'%s',\n", hex.EncodeToString(payload))
	fmt.Fprintf(&b, "  / signature /\n")
	b.WriteString(formatHexBlock(sig, 0))
	b.WriteString("])")
	return b.String()
}

func formatHexBlock(data []byte, indent int) string {
	hexStr := hex.EncodeToString(data)
	prefix := strings.Repeat(" ", indent)
	var b strings.Builder
	b.WriteString(prefix + "h'")
	lineLen := 64
	for i := 0; i < len(hexStr); i += lineLen {
		end := i + lineLen
		if end > len(hexStr) {
			end = len(hexStr)
		}
		if i == 0 {
			b.WriteString(hexStr[i:end])
		} else {
			b.WriteString("\n" + prefix + "  " + hexStr[i:end])
		}
	}
	b.WriteString("',\n")
	return b.String()
}

func buildCOSESign1CBOR(protectedBytes, payload, sig []byte) []byte {
	sign1 := cbor.Tag{
		Number: 18,
		Content: []interface{}{
			protectedBytes,
			map[interface{}]interface{}{},
			payload,
			sig,
		},
	}
	data, err := cbor.Marshal(sign1)
	if err != nil {
		fatalf("CBOR marshal COSE_Sign1: %v", err)
	}
	return data
}

func buildCOSEKeyCBOR(coseAlg int64, pubBytes, privBytes, kidBytes []byte) []byte {
	coseKey := map[interface{}]interface{}{
		int64(1):  int64(7),
		int64(3):  coseAlg,
		int64(2):  kidBytes,
		int64(-1): pubBytes,
		int64(-2): privBytes,
	}
	em, _ := cbor.CanonicalEncOptions().EncMode()
	data, err := em.Marshal(coseKey)
	if err != nil {
		fatalf("CBOR marshal COSE Key: %v", err)
	}
	return data
}

func writeJSON(path string, v interface{}) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatalf("JSON marshal: %v", err)
	}
	writeFile(path, string(data))
}

func writeFile(path, content string) {
	if err := os.WriteFile(path, []byte(content+"\n"), 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func writeFileBytes(path string, data []byte) {
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fatalf("write %s: %v", path, err)
	}
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
