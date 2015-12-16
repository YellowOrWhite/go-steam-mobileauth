package mobileauth

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/cookiejar"
	"net/url"
	"strconv"
)

// ErrMustProvidePhoneNumber is returned by AddAuthenticator
// when no phone set on both authentication linker and account
var ErrMustProvidePhoneNumber = errors.New("no phone number on the account")

// ErrMustRemovePhoneNumber is returned by AddAuthenticator
// when phone is set on both authentication linker and account
var ErrMustRemovePhoneNumber = errors.New("a phone number is already on the account")

// ErrAuthenticatorPresent is returned by AddAuthenticator
var ErrAuthenticatorPresent = errors.New("authenticator already present")

// ErrBadSMSCode is returned by FinalizeAddAuthenticator
// when steam rejects supplied SMS code
var ErrBadSMSCode = errors.New("bad sms code")

// ErrUnableToGenerateCorrectCodes is returned by FinalizeAddAuthenticator
var ErrUnableToGenerateCorrectCodes = errors.New("unable to generate correct codes")

// Handles the linking process for a new mobile authenticator
type AuthenticatorLinker struct {
	// Set to register a new phone number when linking.
	// If a phone number is not set on the account, this must be set.
	// If a phone number is set on the account, this must be null.
	PhoneNumber string
	// Randomly-generated device ID. Should only be generated once per linker.
	DeviceID string
	// After the initial link step, if successful, this will be
	// the SteamGuard data for the account. PLEASE save this somewhere
	// after generating it; it's vital data.
	LinkedAccount *SteamGuardAccount
	// True if the authenticator has been fully finalized.
	finalized bool

	_session *SessionData
	_cookies *cookiejar.Jar
}

func NewAuthenticatorLinker(session *SessionData) *AuthenticatorLinker {
	cookies, _ := cookiejar.New(nil)
	session.AddCookies(cookies)

	return &AuthenticatorLinker{
		DeviceID: generateDeviceID(),
		_session: session,
		_cookies: cookies,
	}
}

func (al *AuthenticatorLinker) AddAuthenticator() error {
	hasPhone, _ := al._hasPhoneAttached()
	if hasPhone && al.PhoneNumber != "" {
		return ErrMustRemovePhoneNumber
	}
	if !hasPhone && al.PhoneNumber == "" {
		return ErrMustProvidePhoneNumber
	}

	if !hasPhone {
		if err := al._addPhoneNumber(); err != nil {
			return fmt.Errorf("failed to add phone number: %v", err)
		}
	}

	postData := url.Values{}
	postData.Set("access_token", al._session.OAuthToken)
	postData.Set("steamid", strconv.FormatUint(al._session.SteamID, 10))
	postData.Set("authenticator_type", "1")
	postData.Set("device_identifier", al.DeviceID)
	postData.Set("sms_phone_id", "1")

	respBody, err := MobileLoginRequest(UrlSteamApiBase+"/ITwoFactorService/AddAuthenticator/v0001", "POST", &postData, nil, nil)
	if err != nil {
		return err
	}

	// Unmarshal response
	r := addAuthenticatorResponse{}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return err
	}
	if r.Response == nil {
		return errors.New("steam returned empty add authenticator response")
	}
	if r.Response.Status == 29 {
		return ErrAuthenticatorPresent
	}
	if r.Response.Status != 1 {
		return fmt.Errorf("authenticator response status: %v\n", r.Response.Status)
	}

	al.LinkedAccount = r.Response
	al.LinkedAccount.Session = al._session
	al.LinkedAccount.DeviceID = al.DeviceID

	return nil
}

func (al *AuthenticatorLinker) FinalizeAddAuthenticator(smsCode string) error {
	var isSmsCodeGood bool
	postData := url.Values{}
	postData.Set("steamid", strconv.FormatUint(al._session.SteamID, 10))
	postData.Set("access_token", al._session.OAuthToken)
	postData.Set("activation_code", smsCode)
	postData.Set("authenticator_code", "")
	retryCount := 30
	for tries := 0; tries <= retryCount; tries++ {
		var steamGuardCode string
		if tries != 0 {
			var err error
			steamGuardCode, err = al.LinkedAccount.GenerateSteamGuardCode()
			if err != nil {
				return fmt.Errorf("failed to generate steam guard code: %v", err)
			}
		}
		postData.Set("authenticator_code", steamGuardCode)
		postData.Set("authenticator_time", strconv.FormatInt(GetSteamTime(), 10))

		if isSmsCodeGood {
			postData.Set("activation_code", "")
		}

		respBody, err := MobileLoginRequest(UrlSteamApiBase+"/ITwoFactorService/FinalizeAddAuthenticator/v0001", "POST", &postData, nil, nil)
		if err != nil {
			return err
		}

		r := finalizeAuthenticatorResponse{}
		if err := json.Unmarshal(respBody, &r); err != nil {
			return err
		}

		if r.Response == nil {
			return errors.New("steam returned empty finalize authenticator response")
		}

		if r.Response.Status == 89 {
			return ErrBadSMSCode
		}

		if r.Response.Status == 88 {
			if tries >= retryCount {
				return ErrUnableToGenerateCorrectCodes
			}
		}

		if !r.Response.Success {
			return errors.New("steam returned success false")
		}

		if r.Response.WantMore {
			isSmsCodeGood = true
			continue
		}

		al.LinkedAccount.FullyEnrolled = true
		return nil
	}

	return fmt.Errorf("failed to finalize authenticator in %v tries\n", retryCount)
}

func (al *AuthenticatorLinker) _addPhoneNumber() error {
	postData := url.Values{}
	postData.Set("op", "add_phone_number")
	postData.Set("arg", al.PhoneNumber)
	postData.Set("sessionid", al._session.SessionID)

	respBody, err := WebRequest(UrlCommunityBase+"/steamguard/phoneajax", "POST", &postData, al._cookies, nil, nil)
	if err != nil {
		return err
	}

	r := addPhoneResponse{}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return err
	}
	if r.Success != true {
		return errors.New("steam returned success false")
	}
	return nil
}

func (al *AuthenticatorLinker) _hasPhoneAttached() (bool, error) {
	postData := url.Values{}
	postData.Set("op", "has_phone")
	postData.Set("arg", "null")
	postData.Set("sessionid", al._session.SessionID)

	respBody, err := MobileLoginRequest(UrlCommunityBase+"/steamguard/phoneajax", "POST", &postData, al._cookies, nil)
	if err != nil {
		return false, err
	}

	r := hasPhoneResponse{}
	if err := json.Unmarshal(respBody, &r); err != nil {
		return false, err
	}

	return r.HasPhone, nil
}

type addAuthenticatorResponse struct {
	Response *SteamGuardAccount
}

type finalizeAuthenticatorResponse struct {
	Response *finalizeAuthenticatorResult
}

type finalizeAuthenticatorResult struct {
	Status     int32
	ServerTime int64 `json:"server_time,string"`
	WantMore   bool  `json:"want_more"`
	Success    bool
}

type hasPhoneResponse struct {
	HasPhone bool `json:"has_phone"`
}

type addPhoneResponse struct {
	Success bool
}

func generateDeviceID() string {
	// Generate 8 random bytes
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic("Failed to read from source of random bytes")
	}
	// Generate sha1 hash
	hasher := sha1.New()
	hasher.Write(b)
	deviceId := make([]byte, 40)
	hex.Encode(deviceId, hasher.Sum(nil))
	deviceId = deviceId[:32]
	// Insert "-" at 8,12,16,20 positions
	for i, pos := range []int{8, 12, 16, 20} {
		deviceId = append(deviceId[0:pos+i],
			append([]byte{'-'}, deviceId[pos+i:]...)...)
	}
	return "android:" + string(deviceId)
}
