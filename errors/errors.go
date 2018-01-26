package errors

import (
	"errors"
)

const callStackDepth = 10

type DetailError interface {
	error
	ErrCoder
	CallStacker
	GetRoot()  error
}


func  NewErr(errmsg string) error {
	return errors.New(errmsg)
}

func NewDetailErr(err error,errcode ErrCode,errmsg string) DetailError{
	if err == nil {return nil}

	derr, ok := err.(DetailedError)
	if !ok {
		derr.root = err
		derr.errmsg = err.Error()
		derr.callstack = getCallStack(0, callStackDepth)
		derr.code = errcode

	}
	if errmsg != "" {
		derr.errmsg = errmsg + ": " + derr.errmsg
	}


	return derr
}

func RootErr(err error) error {
	if err, ok := err.(DetailError); ok {
		return err.GetRoot()
	}
	return err
}



