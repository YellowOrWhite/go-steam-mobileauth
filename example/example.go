package main

import (
	"encoding/json"
	"fmt"
	"github.com/YellowOrWhite/go-steam-mobileauth"
	"io/ioutil"
	"strconv"
)

func main() {
	// This basic loop will log into user accounts you specify, enable the mobile authenticator, and save a maFile (mobile authenticator file)
	for {
		fmt.Print("Enter username: ")
		var username string
		fmt.Scanln(&username)
		fmt.Print("Enter password: ")
		var password string
		fmt.Scanln(&password)
		ul := mobileauth.NewUserLogin(username, password)
		for {
			if err := ul.DoLogin(); err != nil {
				switch err {
				case mobileauth.ErrNeedEmail:
					fmt.Print("Please enter your email code: ")
					var code string
					fmt.Scanln(&code)
					ul.EmailCode = code
				case mobileauth.ErrNeedCaptcha:
					fmt.Println("https://steamcommunity.com/public/captcha.php?gid=" + ul.CaptchaGID)
					fmt.Println("Please follow link to get captcha text.")
					fmt.Print("Please enter captcha text: ")
					var captchaText string
					fmt.Scanln(&captchaText)
					ul.CaptchaText = captchaText
				case mobileauth.ErrNeed2FA:
					fmt.Print("Please enter your mobile authenticator code: ")
					var code string
					fmt.Scanln(&code)
					ul.TwoFactorCode = code
				default:
					fmt.Printf("Failed to login: %v\n", err)
					return
				}
			} else {
				break
			}
		}

		linker := mobileauth.NewAuthenticatorLinker(ul.Session)
		linker.PhoneNumber = "" // Set this to add a new phone number to the account.
		if err := linker.AddAuthenticator(); err != nil {
			fmt.Printf("Failed to add authenticator: %v\n", err)
			continue
		}

		fileContent, err := json.Marshal(linker.LinkedAccount)
		if err != nil {
			panic("Failed to marshal LinkedAccount. For security, authenticator will not be finalized.")
		}
		fileName := strconv.FormatUint(linker.LinkedAccount.Session.SteamID, 10) + ".maFile"
		// write file
		err = ioutil.WriteFile(fileName, fileContent, 0644)
		if err != nil {
			panic("Failed to save maFile. For security, authenticator will not be finalized.")
		}

		fmt.Print("Please enter SMS code: ")
		var smsCode string
		fmt.Scanln(&smsCode)
		if err = linker.FinalizeAddAuthenticator(smsCode); err != nil {
			fmt.Printf("Failed to finalize authenticator: %v\n", err)
		}
	}
}
