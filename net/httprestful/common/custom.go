package common

import (
	"bytes"
	"encoding/json"
	"time"
	"math/rand"

	. "DNA/common"
	tx "DNA/core/transaction"
	. "DNA/errors"
	. "DNA/net/httpjsonrpc"
	Err "DNA/net/httprestful/error"
	"DNA/net/message"
)

const (
	AttributeMaxLen = 252
	MinUserNameLen  = 4
	MaxUserNameLen  = 32
	MinChatMsgLen   = 1
	MaxChatMsgLen   = 1024
)

//record
func getRecordData(cmd map[string]interface{}) ([]byte, int64) {
	if raw, ok := cmd["Raw"].(string); ok && raw == "1" {
		str, ok := cmd["RecordData"].(string)
		if !ok {
			return nil, Err.INVALID_PARAMS
		}
		bys, err := HexStringToBytes(str)
		if err != nil {
			return nil, Err.INVALID_PARAMS
		}
		return bys, Err.SUCCESS
	}
	type Data struct {
		Algrithem string `json:Algrithem`
		Hash      string `json:Hash`
		Signature string `json:Signature`
		Text      string `json:Text`
	}
	type RecordData struct {
		CAkey     string  `json:CAkey`
		Data      Data    `json:Data`
		SeqNo     string  `json:SeqNo`
		Timestamp float64 `json:Timestamp`
	}

	tmp := &RecordData{}
	reqRecordData, ok := cmd["RecordData"].(map[string]interface{})
	if !ok {
		return nil, Err.INVALID_PARAMS
	}
	reqBtys, err := json.Marshal(reqRecordData)
	if err != nil {
		return nil, Err.INVALID_PARAMS
	}

	if err := json.Unmarshal(reqBtys, tmp); err != nil {
		return nil, Err.INVALID_PARAMS
	}
	tmp.CAkey, ok = cmd["CAkey"].(string)
	if !ok {
		return nil, Err.INVALID_PARAMS
	}
	repBtys, err := json.Marshal(tmp)
	if err != nil {
		return nil, Err.INVALID_PARAMS
	}
	return repBtys, Err.SUCCESS
}
func getInnerTimestamp() ([]byte, int64) {
	type InnerTimestamp struct {
		InnerTimestamp float64 `json:InnerTimestamp`
	}
	tmp := &InnerTimestamp{InnerTimestamp: float64(time.Now().Unix())}
	repBtys, err := json.Marshal(tmp)
	if err != nil {
		return nil, Err.INVALID_PARAMS
	}
	return repBtys, Err.SUCCESS
}
func SendRecord(cmd map[string]interface{}) map[string]interface{} {
	resp := ResponsePack(Err.SUCCESS)
	var recordData []byte
	var innerTime []byte
	innerTime, resp["Error"] = getInnerTimestamp()
	if innerTime == nil {
		return resp
	}
	recordData, resp["Error"] = getRecordData(cmd)
	if recordData == nil {
		return resp
	}

	var inputs []*tx.UTXOTxInput
	var outputs []*tx.TxOutput

	transferTx, _ := tx.NewTransferAssetTransaction(inputs, outputs)

	rcdInner := tx.NewTxAttribute(tx.Description, innerTime)
	transferTx.Attributes = append(transferTx.Attributes, &rcdInner)

	bytesBuf := bytes.NewBuffer(recordData)

	buf := make([]byte, AttributeMaxLen)
	for {
		n, err := bytesBuf.Read(buf)
		if err != nil {
			break
		}
		var data = make([]byte, n)
		copy(data, buf[0:n])
		record := tx.NewTxAttribute(tx.Description, data)
		transferTx.Attributes = append(transferTx.Attributes, &record)
	}
	if errCode := VerifyAndSendTx(transferTx); errCode != ErrNoError {
		resp["Error"] = int64(errCode)
		return resp
	}
	hash := transferTx.Hash()
	resp["Result"] = BytesToHexString(hash.ToArrayReverse())
	return resp
}

func SendRecordTransaction(cmd map[string]interface{}) map[string]interface{} {
	resp := ResponsePack(Err.SUCCESS)
	var recordData []byte
	recordData, resp["Error"] = getRecordData(cmd)
	if recordData == nil {
		return resp
	}
	recordType := "record"
	recordTx, _ := tx.NewRecordTransaction(recordType, recordData)

	hash := recordTx.Hash()
	resp["Result"] = BytesToHexString(hash.ToArrayReverse())
	if errCode := VerifyAndSendTx(recordTx); errCode != ErrNoError {
		resp["Error"] = int64(errCode)
		return resp
	}
	return resp
}

func SendChatMessage(cmd map[string]interface{}) map[string]interface{} {
	resp := ResponsePack(Err.SUCCESS)

	address, ok := cmd["Address"].(string)
	if !ok {
		resp["Error"] = Err.INVALID_PARAMS
		return resp
	}
	if len(address) != 0 {
		if _, err := ToScriptHash(address); err != nil {
			resp["Error"] = Err.INVALID_PARAMS
			return resp
		}
	}

	userName, ok := cmd["Username"].(string)
	if !ok {
		resp["Error"] = Err.INVALID_PARAMS
		return resp
	}
	if len(userName) < MinUserNameLen || len(userName) > MaxUserNameLen {
		resp["Error"] = Err.INVALID_PARAMS
		return resp
	}

	content, ok := cmd["Message"].(string)
	if !ok {
		resp["Error"] = Err.INVALID_PARAMS
		return resp
	}
	if len(content) < MinChatMsgLen || len(content) > MaxChatMsgLen {
		resp["Error"] = Err.INVALID_PARAMS
		return resp
	}

	m := &message.ChatPayload{
		Address:  address,
		UserName: userName,
		Content:  []byte(content),
		Nonce: rand.Uint64(),
	}

	if err := node.Xmit(m); err != nil {
		resp["Error"] = Err.INTERNAL_ERROR
		return resp
	}
	resp["Result"] = true

	return resp
}
