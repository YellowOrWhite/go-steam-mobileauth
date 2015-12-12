package mobileauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"time"
)

var ErrBadRSA = errors.New("bad RSA")
var ErrBadCredentials = errors.New("bad credentials")
var ErrNeedCaptcha = errors.New("need captcha")
var ErrNeed2FA = errors.New("need 2FA")
var ErrNeedEmail = errors.New("need email")

// Handles logging the user into the mobile Steam website. Necessary to generate OAuth token and session cookies.
type UserLogin struct {
	Username string
	Password string
	SteamID  uint64

	RequiresCaptcha bool
	CaptchaGID      string
	CaptchaText     string

	RequiresEmail bool
	EmailDomain   string
	EmailCode     string

	Requires2FA   bool
	TwoFactorCode string

	Session  *SessionData
	LoggedIn bool

	_cookies *cookiejar.Jar
}

func NewUserLogin(username, password string) *UserLogin {
	cookies, _ := cookiejar.New(nil)
	return &UserLogin{
		Username: username,
		Password: password,
		_cookies: cookies,
	}
}

func (ul *UserLogin) DoLogin() error {
	cookies := ul._cookies
	if len(cookies.Cookies(cookiePath)) == 0 {
		//Generate a SessionID
		cookies.SetCookies(cookiePath, []*http.Cookie{
			&http.Cookie{
				Name:   "mobileClientVersion",
				Value:  "0 (2.1.3)",
				Path:   "/",
				Domain: ".steamcommunity.com",
			},
			&http.Cookie{
				Name:   "mobileClient",
				Value:  "android",
				Path:   "/",
				Domain: ".steamcommunity.com",
			},
			&http.Cookie{
				Name:   "Steam_Language",
				Value:  "english",
				Path:   "/",
				Domain: ".steamcommunity.com",
			},
		})
		headers := make(map[string]string)
		headers["X-Requested-With"] = "com.valvesoftware.android.steam.community"

		_, err := MobileLoginRequest(UrlCommunityBase+"/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client", "GET", nil, cookies, &headers)
		if err != nil {
			return err
		}
	}

	postData := url.Values{}
	postData.Set("username", ul.Username)
	respBody, err := MobileLoginRequest(UrlCommunityBase+"/login/getrsakey", "POST", &postData, cookies, nil)
	if err != nil {
		return err
	}

	r := RSAResponse{}
	if err = json.Unmarshal(respBody, &r); err != nil {
		return err
	}
	if !r.Success {
		return ErrBadRSA
	}

	// Rsa modulus
	modulusBytes, err := hex.DecodeString(r.Modulus)
	if err != nil {
		return err
	}
	modulus := big.NewInt(0)
	modulus.SetBytes(modulusBytes)
	// Rsa exponent
	exponentBytes, err := hex.DecodeString(r.Exponent)
	if err != nil {
		return err
	}
	exponent := big.NewInt(0)
	exponent.SetBytes(exponentBytes)
	// Generate encrypted password
	publicKey := rsa.PublicKey{
		N: modulus,
		E: int(exponent.Int64()),
	}
	passwordBytes := []byte(ul.Password)
	encryptedPasswordBytes, err := rsa.EncryptPKCS1v15(rand.Reader, &publicKey, passwordBytes)
	if err != nil {
		return err
	}
	encryptedPassword := base64.StdEncoding.EncodeToString(encryptedPasswordBytes)

	// Create request params
	postData = url.Values{}
	postData.Set("username", ul.Username)
	postData.Set("password", encryptedPassword)
	postData.Set("twofactorcode", ul.TwoFactorCode)

	// TODO: is this parameters not required???
	if ul.RequiresCaptcha {
		postData.Set("captchagid", ul.CaptchaGID)
		postData.Set("captcha_text", ul.CaptchaText)
	}

	if ul.Requires2FA || ul.RequiresEmail {
		postData.Set("emailsteamid", strconv.FormatUint(ul.SteamID, 10))
	}
	if ul.RequiresEmail {
		postData.Set("emailauth", ul.EmailCode)
	}
	postData.Set("rsatimestamp", r.Timestamp)
	postData.Set("remember_login", "false")
	postData.Set("oauth_client_id", "DE45CD61")
	postData.Set("oauth_scope", "read_profile write_profile read_client write_client")
	postData.Set("loginfriendlyname", "#login_emailauth_friendlyname_mobile")
	postData.Set("donotcache", strconv.FormatInt(time.Now().Unix(), 10))

	// Make request
	respBody, err = MobileLoginRequest(UrlCommunityBase+"/login/dologin", "POST", &postData, cookies, nil)
	if err != nil {
		return err
	}

	// Process response
	r2 := LoginResponse{}
	if err = json.Unmarshal(respBody, &r2); err != nil {
		return err
	}
	if r2.CaptchaNeeded {
		ul.RequiresCaptcha = true
		ul.CaptchaGID = r2.CaptchaGID.String()
		return ErrNeedCaptcha
	}
	if r2.EmailAuthNeeded {
		ul.RequiresEmail = true
		ul.SteamID = r2.EmailSteamID
		return ErrNeedEmail
	}
	if r2.TwoFactorNeeded && !r2.Success {
		ul.Requires2FA = true
		return ErrNeed2FA
	}
	if !r2.LoginComplete {
		return ErrBadCredentials
	}
	if r2.OAuth == nil || r2.OAuth.OAuthToken == "" {
		return errors.New("steam does not return oauth data")
	}

	// Get sessionid from cookies
	var sessionID string
	for _, cookie := range cookies.Cookies(cookiePath) {
		if cookie.Name == "sessionid" {
			sessionID = cookie.Value
		}
	}

	// Set session data
	stringSteamID := strconv.FormatUint(r2.OAuth.SteamID, 10)
	session := SessionData{
		OAuthToken:       r2.OAuth.OAuthToken,
		SteamID:          r2.OAuth.SteamID,
		SteamLogin:       stringSteamID + "%7C%7C" + r2.OAuth.SteamLogin,
		SteamLoginSecure: stringSteamID + "%7C%7C" + r2.OAuth.SteamLoginSecure,
		WebCookie:        r2.OAuth.Webcookie,
		SessionID:        sessionID,
	}
	ul.Session = &session
	ul.LoggedIn = true

	return nil
}

type LoginResponse struct {
	Success         bool         `json:"success"`
	LoginComplete   bool         `json:"login_complete"`
	OAuth           *OAuthResult `json:"oauth"`
	CaptchaNeeded   bool         `json:"captcha_needed"`
	CaptchaGID      UniStr       `json:"captcha_gid"`
	EmailSteamID    uint64       `json:"emailsteamid,string"`
	EmailAuthNeeded bool         `json:"emailauth_needed"`
	TwoFactorNeeded bool         `json:"requires_twofactor"`
}

type OAuthResult struct {
	SteamID          uint64 `json:"steamid,string"`
	OAuthToken       string `json:"oauth_token"`
	SteamLogin       string `json:"wgtoken"`
	SteamLoginSecure string `json:"wgtoken_secure"`
	Webcookie        string `json:"webcookie"`
}

func (o *OAuthResult) UnmarshalJSON(data []byte) error {
	// no oauth data
	if len(data) < 4 {
		return nil
	}
	// unquote
	unquotedData, err := strconv.Unquote(string(data))
	if err != nil {
		return errors.New("failed to unquote oauth data")
	}
	// unmarshal
	type Alias OAuthResult
	aux := (*Alias)(o)
	if err = json.Unmarshal([]byte(unquotedData), &aux); err != nil {
		return err
	}
	return nil
}

type RSAResponse struct {
	Success   bool   `json:"success"`
	Exponent  string `json:"publickey_exp"`
	Modulus   string `json:"publickey_mod"`
	Timestamp string `json:"timestamp"`
	SteamID   uint64 `json:"steamid"`
}
