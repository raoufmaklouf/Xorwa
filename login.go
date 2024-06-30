package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"time"

	//"log"
	"net/http"
)

func PostParametersLogin(url, method string, hiddenParams map[string]string, usernameField, usernameValue, passwordField, passwordValue string, Cookies []*http.Cookie) (*http.Response, error) {
	// Implement logic for POST Parameters login here

	//log.Println(">>>>>>>>>>>>>>>>>>>>>>>>>> ", url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   20 * time.Second,
	}

	var extraParams string
	if len(hiddenParams) > 0 {
		for key, val := range hiddenParams {
			extraParams += key + "=" + val

		}
	}

	body := bytes.NewBufferString(fmt.Sprintf("%s=%s&%s=%s&"+extraParams, usernameField, usernameValue, passwordField, passwordValue))
	//log.Println(body)
	req, err := http.NewRequest(method, url, body)
	//fmt.Println(err)
	if err != nil {
		return nil, err
	}

	for _, cookie := range Cookies {
		req.AddCookie(cookie)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	//log.Println(req, "=======================================================================\n")
	return client.Do(req)
}
