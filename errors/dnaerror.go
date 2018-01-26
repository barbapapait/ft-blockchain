package errors

type DetailedError struct {
	errmsg string
	callstack *CallStack
	root error
	code ErrCode
}

func (e DetailedError) Error() string {
	return e.errmsg
}

func (e DetailedError) GetErrCode()  ErrCode {
	return e.code
}

func (e DetailedError) GetRoot()  error {
	return e.root
}

func (e DetailedError) GetCallStack()  *CallStack {
	return e.callstack
}
