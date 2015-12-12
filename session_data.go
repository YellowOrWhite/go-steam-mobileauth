package mobileauth

import (
	"net/http"
	"net/http/cookiejar"
	"strconv"
)

type SessionData struct {
	SessionID        string
	SteamLogin       string
	SteamLoginSecure string
	WebCookie        string
	OAuthToken       string
	SteamID          uint64
}

func (sd *SessionData) AddCookies(cookies *cookiejar.Jar) {
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
		&http.Cookie{
			Name:   "steamid",
			Value:  strconv.FormatUint(sd.SteamID, 10),
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
		&http.Cookie{
			Name:     "steamLogin",
			Value:    sd.SteamLogin,
			Path:     "/",
			Domain:   ".steamcommunity.com",
			HttpOnly: true,
		},
		&http.Cookie{
			Name:     "steamLoginSecure",
			Value:    sd.SteamLoginSecure,
			Path:     "/",
			Domain:   ".steamcommunity.com",
			Secure:   true,
			HttpOnly: true,
		},
		&http.Cookie{
			Name:   "dob",
			Value:  "",
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
		&http.Cookie{
			Name:   "sessionid",
			Value:  sd.SessionID,
			Path:   "/",
			Domain: ".steamcommunity.com",
		},
	})
}
