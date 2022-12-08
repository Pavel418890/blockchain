// Package signature provides helper functions for handling the blockchain
// signature needs.
package signature

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

// plotsID is an arbitrary number for signing messages. This will make it
// clear that the signature comes from the PLots blockchain.
// Ethereum and Bitcoin dot this as well, but they use the value of 27.
const plotsID = 29

// ============================================================================

// Sign uses the specified private key to sign the transaction.
func Sign(value any, privateKey *ecdsa.PrivateKey) (v, r, s *big.Int, err error) {

	// Prepare the transaction for signing.
	data, err := stamp(value)
	if err != nil {
		return nil, nil, nil, err
	}

	// Sign the hash with the private key to prduce a signature.
	sig, err := crypto.Sign(data, privateKey)
	if err != nil {
		return nil, nil, nil, err
	}

	// Convert the 65 byte signature into the [R|S|V] format.
	v, r, s = toSignatureValues(sig)
	return v, r, s, nil
}

func stamp(value any) ([]byte, error) {

	// Marshal the data.
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}

	// Hash the transaction data into a 32 byte array.: This will provide
	// a data length consistency with all transactions.
	txHash := crypto.Keccak256(data)

	// Convert the stamp into a slice of bytes. This stamp is used so signature
	// we produce  when sidning transactions are always unique to the PLots
	// blockchain.
	stamp := []byte("\x19Plots Signed Message:\n32")

	// Hash the stamp and txHash together in a final 32 byte array
	// that represents the transaction data.
	tran := crypto.Keccak256(stamp, txHash)
	return tran, nil
}

// toSignatureValues converts the signature info the r, s, v values.
func toSignatureValues(sig []byte) (v, r, s *big.Int) {
	r = new(big.Int).SetBytes(sig[:32])
	s = new(big.Int).SetBytes(sig[32:64])
	v = new(big.Int).SetBytes([]byte{sig[64] + plotsID})

	return v, r, s
}

// VerifySignature verifies the signature conforms to our stadards and
// is associated with the data claimed to be signed.
func VerifySignature(value any, v, r, s *big.Int) error {

	// Check the recovery id is either 0 or 1.
	uintV := v.Uint64() - plotsID
	if uintV != 0 && uintV != 1 {
		return errors.New("invalid recovery id")
	}

	// Check the signature values are valid.
	if !crypto.ValidateSignatureValues(byte(uintV), r, s, false) {
		return errors.New("invalid signature values")
	}

	// Prepare the transaction for recovery and validation.
	data, err := stamp(value)
	if err != nil {
		return err
	}

	// Convert the [R|S|V] format into the original 65 bytes.
	sig := ToSignatureBytes(v, r, s)

	// Capture the uncompressed public key associated with this signature.
	sigPublicKey, err := crypto.Ecrecover(data, sig)
	if err != nil {
		return fmt.Errorf("ecrecover, %w", err)
	}

	// Check that the given public key created the signature over the data.
	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(sigPublicKey, data, rs) {
		return errors.New("invalid signature")
	}

	return nil
}

// FromAddress extracts theaddress for the account that signed the transaction.
func FromAddress(value any, v, r, s *big.Int) (string, error) {

	// Prepare the transaction for public key extraction.
	data, err := stamp(value)
	if err != nil {
		return "", err
	}

	// Convert the [R|V|S] format into the original 65 bytes.
	sig := ToSignatureBytes(v, r, s)

	// Validate the signature since there can be conversion issues
	// between [R|S|V] to []bytes. Leading 0's are truncated by big package.
	var sigPublicKey []byte
	{
		sigPublicKey, err = crypto.Ecrecover(data, sig)
		if err != nil {
			return "", err
		}

		rs := sig[:crypto.RecoveryIDOffset]
		if !crypto.VerifySignature(sigPublicKey, data, rs) {
			return "", errors.New("invalid signature")
		}
	}

	// Capture the public key asociated with this signature.
	x, y := elliptic.Unmarshal(crypto.S256(), sigPublicKey)
	publicKey := ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}

	// Extract the account address fro the public key.
	return crypto.PubkeyToAddress(publicKey).String(), nil
}

// ============================================================================

// ToSignatureBytes converts the r, s, v  values into a slice of bytes
// with the removal of the plotsID.
func ToSignatureBytes(v, r, s *big.Int) []byte {
	sig := make([]byte, crypto.SignatureLength)

	rBytes := r.Bytes()
	if len(rBytes) == 31 {
		copy(sig[1:], rBytes)
	} else {
		copy(sig, rBytes)
	}

	sBytes := s.Bytes()
	if len(sBytes) == 31 {
		copy(sig[1:], sBytes)
	} else {
		copy(sig, sBytes)
	}

	sig[64] = byte(v.Uint64() - plotsID)

	return sig
}
