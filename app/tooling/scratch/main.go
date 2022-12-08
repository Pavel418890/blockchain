package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	err := sign()
	if err != nil {
		log.Fatalln(err)
	}
}
func sign() error {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return err
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey).String()
	fmt.Println(address)
	v := struct {
		Name string
	}{
		Name: "Bill",
	}

	data, err := stamp(v)
	if err != nil {
		return fmt.Errorf("stamp: %w", err)
	}

	// Sign the hash with private key to produce a signature.
	sig, err := crypto.Sign(data, privateKey)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}

	fmt.Printf("SIG: 0x%s\n", hex.EncodeToString(sig))

	// ========================================================================
	sigPublicKey, err := crypto.Ecrecover(data, sig)
	if err != nil {
		return err
	}
	// Capture the public key associated with this signature.
	x, y := elliptic.Unmarshal(crypto.S256(), sigPublicKey)
	publicKey := ecdsa.PublicKey{Curve: crypto.S256(), X: x, Y: y}

	// Extract the account address from the public key.
	address = crypto.PubkeyToAddress(publicKey).String()
	fmt.Println(address)
	return nil

	// ========================================================================
	// NODE

	// Passed with the sig
	v2 := struct {
		Name string
	}{
		Name: "Billy",
	}

	data2, err := stamp(v2)
	if err != nil {
		return fmt.Errorf("stamp: %w", err)
	}

	// Sign the hash with private key to produce a signature.
	sig, err = crypto.Sign(data2, privateKey)
	if err != nil {
		return fmt.Errorf("sign: %w", err)
	}
	sigPublicKey, err = crypto.Ecrecover(data2, sig)
	if err != nil {
		return err
	}

	rs := sig[:crypto.RecoveryIDOffset]
	if !crypto.VerifySignature(sigPublicKey, data2, rs) {
		return errors.New("invalid signature")
	}

	// Capture the public key associated with this signature.
	x2, y2 := elliptic.Unmarshal(crypto.S256(), sigPublicKey)
	publicKey = ecdsa.PublicKey{Curve: crypto.S256(), X: x2, Y: y2}

	// Extract the account address from the public key.
	address = crypto.PubkeyToAddress(publicKey).String()
	fmt.Println(address)
	return nil
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
