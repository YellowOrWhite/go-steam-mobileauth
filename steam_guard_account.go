package mobileauth

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var confIDRegex = regexp.MustCompile("data-confid=\"(\\d+)\"")
var confKeyRegex = regexp.MustCompile("data-key=\"(\\d+)\"")
var confDescRegex = regexp.MustCompile("<div>((Confirm|Trade with|Sell -) .+)</div>")

type SteamGuardAccount struct {
	SharedSecret   string `json:"shared_secret"`
	SerialNumber   string `json:"serial_number"`
	RevocationCode string `json:"revocation_code"`
	URI            string `json:"uri"`
	ServerTime     int64  `json:"server_time,string"`
	AccountName    string `json:"account_name"`
	TokenGID       string `json:"token_gid"`
	IdentitySecret string `json:"identity_secret"`
	Secret1        string `json:"secret_1"`
	Status         int32  `json:"status"`
	DeviceID       string `json:"device_id"`
	// Set to true if the authenticator has actually been applied to the account.
	FullyEnrolled bool         `json:"fully_enrolled"`
	Session       *SessionData `json:"session"`
}

func (a *SteamGuardAccount) DeactivateAuthenticator() error {
	postData := url.Values{}
	postData.Set("steamid", strconv.FormatUint(a.Session.SteamID, 10))
	postData.Set("steamguard_scheme", "2")
	postData.Set("revocation_code", a.RevocationCode)
	postData.Set("access_token", a.Session.OAuthToken)

	respBody, err := MobileLoginRequest(UrlSteamApiBase+"/ITwoFactorService/RemoveAuthenticator/v0001", "POST", &postData, nil, nil)
	if err != nil {
		return err
	}
	r := RemoveAuthenticatorResponse{}
	if err = json.Unmarshal(respBody, &r); err != nil {
		return err
	}
	if r.Response == nil || !r.Response.Success {
		return errors.New("steam returned success false")
	}

	return nil
}

func (a *SteamGuardAccount) GenerateSteamGuardCode() (string, error) {
	return a.GenerateSteamGuardCodeForTime(GetSteamTime())
}

func (a *SteamGuardAccount) GenerateSteamGuardCodeForTime(t int64) (string, error) {
	if a.SharedSecret == "" {
		return "", errors.New("shared secret not set")
	}

	// Shared secret is our key
	sharedSecretBytes, err := base64.StdEncoding.DecodeString(a.SharedSecret)
	if err != nil {
		return "", err
	}

	// Time for code
	t = t / 30 // TODO: why we are doing this???
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(t))

	// Generate hmac
	hmacGenerator := hmac.New(sha1.New, sharedSecretBytes)
	hmacGenerator.Write(timeBytes)
	mac := hmacGenerator.Sum(nil)

	// the last 4 bits of the mac say where the code starts (e.g. if last 4 bit are 1100, we start at byte 12)
	start := int(mac[19] & 0x0f)

	// extract code - 4 bytes
	codeBytes := make([]byte, 4)
	copy(codeBytes, mac[start:])
	fullCode := binary.BigEndian.Uint32(codeBytes)
	fullCode = fullCode & 0x7fffffff

	// character set for authenticator code
	chars := []byte{50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89}

	// build the alphanumeric code
	var textCodeBytes []byte
	for i := 0; i < 5; i++ {
		textCodeBytes = append(textCodeBytes, chars[fullCode%uint32(len(chars))])
		fullCode = fullCode / uint32(len(chars))
	}

	return string(textCodeBytes[:]), nil
}

func (a *SteamGuardAccount) FetchConfirmations() ([]*Confirmation, error) {
	queryParams := a.GenerateConfirmationQueryParams("conf")

	cookies, _ := cookiejar.New(nil)
	a.Session.AddCookies(cookies)

	respBody, err := WebRequest(UrlConfirmationService, "GET", &queryParams, cookies, nil, nil)
	if err != nil {
		return nil, err
	}

	respString := string(respBody)

	// Nothing to confirm
	if strings.Contains(respString, "<div>Nothing to confirm</div>") {
		return nil, nil
	}

	// Try to parse response
	confIDs := confIDRegex.FindAllStringSubmatch(respString, -1)
	confKeys := confKeyRegex.FindAllStringSubmatch(respString, -1)
	confDescs := confDescRegex.FindAllStringSubmatch(respString, -1)

	if confIDs == nil || confKeys == nil || confDescs == nil {
		return nil, errors.New("failed to parse response")
	}

	if len(confIDs) != len(confKeys) || len(confIDs) != len(confDescs) {
		return nil, errors.New("unexpected response format: number of ids, keys and descriptions are not the same")
	}

	// Create confirmations slice
	var confirmations []*Confirmation
	for index, _ := range confIDs {
		cn := &Confirmation{
			ConfirmationID:          confIDs[index][1],
			ConfirmationKey:         confKeys[index][1],
			ConfirmationDescription: confDescs[index][1],
		}
		confirmations = append(confirmations, cn)
	}

	return confirmations, nil
}

func (a *SteamGuardAccount) AcceptConfirmation(cn *Confirmation) error {
	return a._sendConfirmationAjax(cn, "allow")
}

func (a *SteamGuardAccount) DenyConfirmation(cn *Confirmation) error {
	return a._sendConfirmationAjax(cn, "cancel")
}

// Refreshes the Steam session. Necessary to perform confirmations if your session has expired or changed.
func (a *SteamGuardAccount) RefreshSession() error {
	postData := url.Values{}
	postData.Set("access_token", a.Session.OAuthToken)

	respBody, err := WebRequest(UrlMobileAuthGetWGToken, "POST", &postData, nil, nil, nil)
	if err != nil {
		return err
	}

	r := RefreshSessionDataResponse{}
	if err = json.Unmarshal(respBody, &r); err != nil {
		return err
	}
	if r.Response == nil || r.Response.Token == "" {
		return errors.New("malformed response")
	}

	stringSteamID := strconv.FormatUint(a.Session.SteamID, 10)
	token := stringSteamID + "%7C%7C" + r.Response.Token
	tokenSecure := stringSteamID + "%7C%7C" + r.Response.TokenSecure

	a.Session.SteamLogin = token
	a.Session.SteamLoginSecure = tokenSecure

	return nil
}

func (a *SteamGuardAccount) _sendConfirmationAjax(cn *Confirmation, op string) error {
	queryParams := a.GenerateConfirmationQueryParams(op)
	queryParams.Set("op", op)
	queryParams.Set("cid", cn.ConfirmationID)
	queryParams.Set("ck", cn.ConfirmationKey)

	cookies, _ := cookiejar.New(nil)
	a.Session.AddCookies(cookies)

	// TODO: do we need this???
	//referer := urlConfirmationService

	respBody, err := WebRequest(UrlConfirmationService, "GET", &queryParams, cookies, nil, nil)
	if err != nil {
		return err
	}

	r := SendConfirmationResponse{}
	if err = json.Unmarshal(respBody, &r); err != nil {
		return err
	}
	if !r.Success {
		return errors.New("steam returned success false")
	}
	return nil
}

func (a *SteamGuardAccount) GenerateConfirmationQueryParams(tag string) url.Values {
	t := GetSteamTime()
	queryParams := url.Values{}
	queryParams.Set("p", a.DeviceID)
	queryParams.Set("a", strconv.FormatUint(a.Session.SteamID, 10))
	queryParams.Set("k", a._generateConfirmationHashForTime(t, tag))
	queryParams.Set("t", strconv.FormatInt(t, 10))
	queryParams.Set("m", "android")
	queryParams.Set("tag", tag)
	return queryParams
}

func (a *SteamGuardAccount) _generateConfirmationHashForTime(t int64, tag string) string {
	identitySecretBytes, err := base64.StdEncoding.DecodeString(a.IdentitySecret)
	if err != nil {
		// TODO: maybe we shall panic or return error up the chain
		return ""
	}

	data := make([]byte, 8)
	binary.BigEndian.PutUint64(data, uint64(t))
	tagBytes := []byte(tag)
	if len(tagBytes) > 32 {
		// maximum tag length is 32 bytes
		tagBytes = tagBytes[:32]
	}
	data = append(data, tagBytes...)

	// Generate hmac
	hmacGenerator := hmac.New(sha1.New, identitySecretBytes)
	hmacGenerator.Write(data)
	mac := hmacGenerator.Sum(nil)

	return base64.StdEncoding.EncodeToString(mac)
}

type RefreshSessionDataResponse struct {
	Response *RefreshSessionDataResult `json:"response"`
}

type RefreshSessionDataResult struct {
	Token       string `json:"token"`
	TokenSecure string `json:"token_secure"`
}

type RemoveAuthenticatorResponse struct {
	Response *RemoveAuthenticatorResult `json:"response"`
}

type RemoveAuthenticatorResult struct {
	Success bool `json:"success"`
}

type SendConfirmationResponse struct {
	Success bool `json:"success"`
}
