// Package database handles all the lower level support for maintaining the
// blockchain in storage and maintaining an in -memory database of account info.
package database

import (
	"sync"

	"github.com/ardanlabs/blockchain/foundation/blockchain/genesis"
)

// Database manages data related to accounts who have transacted on the blockchain.
type Database struct {
	mu      sync.RWMutex
	genesis genesis.Genesis
	//	latestBlock Block
	accounts map[AccountID]Account
}
