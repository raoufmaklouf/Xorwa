package main

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

type LoginRequestType int

const (
	MultipartFormData LoginRequestType = iota
	AuthorizationBasic
	PostJSON
	PostParameters
	XMLHttpRequest
	Unknown
)

func DetectLoginRequestType(resp *http.Response) (LoginRequestType, error) {
	defer resp.Body.Close()

	// Parse the HTML document
	doc, err := html.Parse(resp.Body)
	if err != nil {
		return Unknown, err
	}

	// Initialize the request type as Unknown
	requestType := Unknown

	// Function to traverse the HTML document tree
	var traverse func(*html.Node)
	traverse = func(n *html.Node) {
		if n.Type == html.ElementNode {
			//log.Printf("Processing node: %s\n", n.Data)
		}

		// Check if the current node is a <form> element
		if n.Type == html.ElementNode && n.Data == "form" {
			//log.Println("Form found")

			// Check the method and enctype attributes of the form
			method := strings.ToLower(getAttribute(n, "method"))
			enctype := strings.ToLower(getAttribute(n, "enctype"))

			if method == "post" {
				switch {
				case enctype == "multipart/form-data" || hasFileInput(n):
					requestType = MultipartFormData
					//log.Println("MultipartFormData detected")
				case enctype == "application/json" || hasJSONData(n):
					requestType = PostJSON
					//log.Println("PostJSON detected")
				case enctype == "application/x-www-form-urlencoded" || enctype == "":
					if hasXMLHttpRequestScript(n) {
						requestType = XMLHttpRequest
						//log.Println("XMLHttpRequest detected within form")
					} else {
						requestType = PostParameters
						//log.Println("PostParameters detected")
					}
				default:
					if hasBasicAuthInputFields(n) {
						requestType = AuthorizationBasic
						//log.Println("AuthorizationBasic detected with default enctype")
					} else if hasXMLHttpRequestScript(n) {
						requestType = XMLHttpRequest
						//log.Println("XMLHttpRequest detected with default enctype")
					} else {
						requestType = PostParameters
						//log.Println("PostParameters detected with default enctype")
					}
				}
			}
		}

		// Recursively check child nodes
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			traverse(c)
		}
	}

	// Initial traversal to detect the form
	traverse(doc)

	// If no form-based request type was detected, check for XMLHttpRequest in the entire document
	if requestType == Unknown && hasXMLHttpRequestScript(doc) {
		requestType = XMLHttpRequest
		//log.Println("XMLHttpRequest detected in scripts")
	}

	if requestType == Unknown {
		return Unknown, fmt.Errorf("unable to determine login request type")
	}

	return requestType, nil
}

func getAttribute(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return strings.ToLower(a.Val)
		}
	}
	return ""
}

// hasBasicAuthInputFields checks if the form contains input fields that suggest basic authorization
func hasBasicAuthInputFields(n *html.Node) bool {
	usernameField := false
	passwordField := false

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			inputType := getAttribute(n, "type")
			name := getAttribute(n, "name")

			if inputType == "text" && (name == "username" || name == "email") {
				usernameField = true
			}
			if inputType == "password" && name == "password" {
				passwordField = true
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)

	return usernameField && passwordField
}

func hasFileInput(n *html.Node) bool {
	var hasFile bool
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "input" {
			if getAttribute(n, "type") == "file" {
				hasFile = true
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return hasFile
}

func hasJSONData(n *html.Node) bool {
	var hasJSON bool
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			if getAttribute(n, "type") == "application/json" {
				hasJSON = true
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)
	return hasJSON
}

func hasXMLHttpRequestScript(n *html.Node) bool {
	var foundXMLHttpRequest bool

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			// Check if the script contains XMLHttpRequest or Fetch API calls
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.TextNode {
					scriptContent := c.Data
					if strings.Contains(scriptContent, "XMLHttpRequest") || containsFetchAPI(scriptContent) {
						foundXMLHttpRequest = true
						return
					}
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(n)

	return foundXMLHttpRequest
}

func containsFetchAPI(scriptContent string) bool {
	// Simple regex to find fetch calls
	fetchRegex := regexp.MustCompile(`\bfetch\s*\(`)
	return fetchRegex.MatchString(scriptContent)
}

// func getAttribute(n *html.Node, attrName string) string {
// 	for _, attr := range n.Attr {
// 		if attr.Key == attrName {
// 			return attr.Val
// 		}
// 	}
// 	return ""
// }
