package httpjsonrpc

var (
	RpcInvalidHash        = responsePacking("invalid hash")
	RpcInvalidBlock       = responsePacking("invalid block")
	RpcInvalidTransaction = responsePacking("invalid transaction")
	RpcInvalidParameter   = responsePacking("invalid parameter")

	RpcUnknownBlock       = responsePacking("unknown block")
	RpcUnknownTransaction = responsePacking("unknown transaction")

	RpcNil           = responsePacking(nil)
	RpcUnsupported   = responsePacking("Unsupported")
	RpcInternalError = responsePacking("internal error")
	RpcIOError       = responsePacking("internal IO error")
	RpcAPIError      = responsePacking("internal API error")
	RpcSuccess       = responsePacking(true)
	RpcFailed        = responsePacking(false)

	RpcReturn = responsePacking
)
