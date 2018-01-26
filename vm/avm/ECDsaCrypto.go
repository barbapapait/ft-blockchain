package avm

import (
	"ft-blockchain/crypto"
	. "ft-blockchain/errors"
	"ft-blockchain/common/log"
	"errors"
	"ft-blockchain/common"
)


type ECDsaCrypto struct  {
}

func (c * ECDsaCrypto) Hash160( message []byte ) []byte {
	temp, _ := common.ToCodeHash(message)
	return temp.ToArray()
}

func (c * ECDsaCrypto) Hash256( message []byte ) []byte {
	return []byte{}
}

func (c * ECDsaCrypto) VerifySignature(message []byte,signature []byte, pubkey []byte) (bool,error) {

	log.Debug("message: %x \n", message)
	log.Debug("signature: %x \n", signature)
	log.Debug("pubkey: %x \n", pubkey)

	pk,err := crypto.DecodePoint(pubkey)
	if err != nil {
		return false,NewDetailErr(errors.New("[ECDsaCrypto], crypto.DecodePoint failed."), ErrNoCode, "")
	}

	err = crypto.Verify(*pk, message,signature)
	if err != nil {
		return false,NewDetailErr(errors.New("[ECDsaCrypto], VerifySignature failed."), ErrNoCode, "")
	}

	return true,nil
}
