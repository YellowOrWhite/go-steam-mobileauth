package mobileauth

import (
	"encoding/json"
)

// Steam JSON has fields which can be either string in normal operation
// or number when some error occurs.
// UniStr unmarshals from string and silently ignores other types
type UniStr string

func (s *UniStr) UnmarshalJSON(data []byte) error {
	// non string
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		*s = UniStr("")
		return nil
	}
	// string
	var aux string
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*s = UniStr(aux)
	return nil
}

func (s UniStr) String() string {
	return string(s)
}
