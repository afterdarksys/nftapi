package feed

// Error is a failure the HTTP layer maps to a status code. Message is safe
// to return to the client: it does not include the feed body or the request.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func errCode(code, msg string) *Error { return &Error{Code: code, Msg: msg} }

func invalid(msg string) *Error     { return errCode("invalid_argument", msg) }
func notFound(msg string) *Error    { return errCode("not_found", msg) }
func unavailable(msg string) *Error { return errCode("unavailable", msg) }
func timeoutErr(msg string) *Error  { return errCode("timeout", msg) }
