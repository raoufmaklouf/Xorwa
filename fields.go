package main

import (
	"net/http"

	"github.com/PuerkitoBio/goquery"
)

func VisitAndDetectLoginElements(resp *http.Response) (*LoginInfo, []*http.Cookie, error) {

	defer resp.Body.Close()
	// Parse the HTML document
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		return nil, nil, err
	}

	// Detect login elements
	loginInfo := &LoginInfo{
		URL:           "",
		Method:        "",
		HiddenParams:  make(map[string]string),
		UsernameField: "",
		PasswordField: "",
		//Cookies: []*http.Cookie,
	}
	Cookies := resp.Cookies()

	doc.Find("form").Each(func(index int, formHtml *goquery.Selection) {
		loginInfo.URL, _ = formHtml.Attr("action")
		loginInfo.Method, _ = formHtml.Attr("method")
		formHtml.Find("input").Each(func(index int, inputHtml *goquery.Selection) {
			paramName, _ := inputHtml.Attr("name")
			paramValue, _ := inputHtml.Attr("value")
			paramType, _ := inputHtml.Attr("type")
			if paramName != "" {
				if paramType == "hidden" {
					loginInfo.HiddenParams[paramName] = paramValue
				} else if paramType == "text" && loginInfo.UsernameField == "" { // if have a defult value set as is not username feld
					loginInfo.UsernameField = paramName
				} else if paramType == "password" && loginInfo.PasswordField == "" {
					loginInfo.PasswordField = paramName
				}
			}
		})
	})

	return loginInfo, Cookies, nil
}
