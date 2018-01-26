package cli

import (
	"math/rand"
	"time"

	"ft-blockchain/common/config"
	"ft-blockchain/common/log"
	"ft-blockchain/crypto"
)

func init() {
	log.Init()
	crypto.SetAlg(config.Parameters.EncryptAlg)
	//seed transaction nonce
	rand.Seed(time.Now().UnixNano())
}
