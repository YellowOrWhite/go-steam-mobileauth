package mobileauth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"
)

// Aligns system time with the Steam server time. Not super advanced; probably not taking some things into account that it should.
// Necessary to generate up-to-date codes. In general, this will have an error of less than a second, assuming Steam is operational.

var _isTimeAligned bool
var _steamTimeDifference int64

func GetSteamTime() int64 {
	if !_isTimeAligned {
		AlignTime()
	}
	return time.Now().Unix() + _steamTimeDifference
}

func AlignTime() error {
	now := time.Now().Unix()
	client := new(http.Client)
	resp, err := client.Post(UrlTwoFactorTimeQuery, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte("steamid=0")))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	r := timeQueryResponse{}
	if err = json.Unmarshal(respBody, &r); err != nil {
		return err
	}
	_steamTimeDifference = r.Response.ServerTime - now
	_isTimeAligned = true
	return nil
}

type timeQueryResponse struct {
	Response *timeQueryResult `json:"response"`
}

type timeQueryResult struct {
	ServerTime int64 `json:"server_time,string"`
}
