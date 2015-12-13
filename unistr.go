package mobileauth

import (
	"encoding/json"
)

// Steam JSON has fields which can be either string in normal operation
// or number when some error occurs.
// UniStr unmarshals from string and silently ignores other types
type uniStr string

func (s *uniStr) UnmarshalJSON(data []byte) error {
	// non string
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		*s = uniStr("")
		return nil
	}
	// string
	var aux string
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	*s = uniStr(aux)
	return nil
}

func (s uniStr) String() string {
	return string(s)
}
