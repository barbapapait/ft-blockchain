package evm

import (
	"math/big"
	"ft-blockchain/vm/evm/common"
)

func memoryMStore(stack *Stack) *big.Int {
	return common.CalcMemSize(stack.Back(0), big.NewInt(32))
}