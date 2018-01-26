package net

import (
	. "ft-blockchain/common"
	"ft-blockchain/core/ledger"
	"ft-blockchain/core/transaction"
	"ft-blockchain/crypto"
	. "ft-blockchain/errors"
	"ft-blockchain/events"
	"ft-blockchain/net/node"
	"ft-blockchain/net/protocol"
)

type Neter interface {
	GetTxnPool(byCount bool) map[Uint256]*transaction.Transaction
	Xmit(interface{}) error
	GetEvent(eventName string) *events.Event
	GetBookKeepersAddrs() ([]*crypto.PubKey, uint64)
	CleanSubmittedTransactions(block *ledger.Block) error
	GetNeighborNoder() []protocol.Noder
	Tx(buf []byte)
	AppendTxnPool(*transaction.Transaction, bool) ErrCode
}

func StartProtocol(pubKey *crypto.PubKey) protocol.Noder {
	net := node.InitNode(pubKey)
	net.ConnectSeeds()

	return net
}
