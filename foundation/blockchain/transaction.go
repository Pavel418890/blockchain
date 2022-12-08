package database

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"

	"github.com/ardanlabs/blockchain/foundation/signature"
)

// ===========================================================================

// Tx is the transactional info between two parties.
type Tx struct {
	ChainID uint16    `json:"chain_id"` // Ethereum: The chain id that is listed in the genesis file.
	Nonce   uint64    `json:"nonce"`    // Ethereum: Unique id for the transaction supplied by the user.
	ToID    AccountID `json:"to"`       // Ethereum: Account receiving the benefit of the transaction.
	Value   uint64    `json:"value"`    // Ethereum: Monetary value received from this transaction.
	Tip     uint64    `json:"tip"`      // Ethereum: Tip offered by the sender as an incentive to mine this transaction.
	Data    []byte    `json:"data"`     // Ethereum: Extra data related to the transaction.
}

// NewTx construct a new transaction.
func NewTx(chainID uint16, nonce uint64, toID AccountID, value uint64, tip uint64, data []byte) (Tx, error) {
	if !toID.IsAccountID() {
		return Tx{}, fmt.Errorf("to account is not properly formatted")
	}

	tx := Tx{
		ChainID: chainID,
		Nonce:   nonce,
		ToID:    toID,
		Value:   value,
		Tip:     tip,
		Data:    data,
	}

	return tx, nil
}

// Sign uses the speciefied private key to sign the transaction.
func (tx Tx) Sign(privateKey *ecdsa.PrivateKey) (SignedTx, error) {

	// Validate the to account address is a avalid address.
	if !tx.ToID.IsAccountID() {
		return SignedTx{}, fmt.Errorf("to account is not properly formatted")
	}

	// Sign the transaction with the private key to produce a signature.
	v, r, s, err := signature.Sign(tx, privateKey)
	if err != nil {
		return SignedTx{}, err
	}

	// Construct the signed transaction by adding the signature
	// in the [R|S|V] format.
	signedTx := SignedTx{
		Tx: tx,
		V:  v,
		R:  r,
		S:  s,
	}

	return signedTx, nil
}

//============================================================================

// SignedTx is a signed version of the trancsaction. This is how clients like
// a wallet provide transactions for inclusion into the blockchain.
type SignedTx struct {
	Tx `json:"tx"`
	V  *big.Int `json:"v"`
	R  *big.Int `json:"r"`
	S  *big.Int `json:"s"`
}

// Validate verifies the transaction has a proper signature that conforms to our
// standards and is associated with the data claimed to be signed. It also
// checks the format of the to account.
func (tx SignedTx) Validate() error {
	if !tx.ToID.IsAccountID() {
		return errors.New("invalid account for to account")
	}
	if err := signature.VerifySignature(tx.Tx, tx.V, tx.R, tx.S); err != nil {
		return err
	}

	return nil
}

// FromAccount extracts the account id that signed the transaction.
func (tx SignedTx) FromAccount() (AccountID, error) {
	address, err := signature.FromAddress(tx.Tx, tx.V, tx.R, tx.S)
	return AccountID(address), err
}

// SignatureString returns the signature as a string.
func (tx SignedTx) SignatureString() string {
	return signature.SignatureString(tx.V, tx.R, tx.S)
}

// Strings implements the fmt.Stringer interface for logging.
func (tx SignedTx) String() string {
	from, err := tx.FromAccount()
	if err != nil {
		from = "unknown"
	}

	return fmt.Sprintf("%s:%d", from, tx.Nonce)
}
