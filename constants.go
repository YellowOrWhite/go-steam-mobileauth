package mobileauth

import (
	"fmt"
	"net/url"
)

// Cookie path
var cookiePath, _ = url.Parse("https://steamcommunity.com/")

// API endpoints
const UrlSteamApiBase string = "https://api.steampowered.com"
const UrlCommunityBase string = "https://steamcommunity.com"
const UrlConfirmationService string = UrlCommunityBase + "/mobileconf"
const UrlMobileAuthBase string = UrlSteamApiBase + "/IMobileAuthService/%s/v0001"
const UrlTwoFactorBase string = UrlSteamApiBase + "/ITwoFactorService/%s/v0001"

var UrlMobileAuthGetWGToken string = fmt.Sprintf(UrlMobileAuthBase, "GetWGToken")
var UrlTwoFactorTimeQuery string = fmt.Sprintf(UrlTwoFactorBase, "QueryTime")
