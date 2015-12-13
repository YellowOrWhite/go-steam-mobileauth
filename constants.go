package mobileauth

import (
	"net/url"
)

// Cookie path
var cookiePath, _ = url.Parse("https://steamcommunity.com/")

const UrlSteamApiBase string = "https://api.steampowered.com"
const UrlCommunityBase string = "https://steamcommunity.com"
const UrlConfirmationService string = UrlCommunityBase + "/mobileconf"
const UrlMobileAuthService string = UrlSteamApiBase + "/IMobileAuthService"
const UrlTwoFactorService string = UrlSteamApiBase + "/ITwoFactorService"
