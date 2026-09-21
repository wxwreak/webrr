package main

import (
	"flag"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/fatih/color"
)

var headersRisks = map[string]string{
	"Content-Security-Policy":   "XSS and Injection prevention",
	"X-Frame-Options":           "Clickjacking prevention",
	"Strict-Transport-Security": "Forces HTTPS connection",
	"X-Content-Type-Options":    "MIME-Sniffing prevention",
	"Referrer-Policy":           "Data leak check in the Referer header",
	"Permission-Policy":         "Restrict access to sensitive functions",
	"X-Powered-By":              "Leaks version of backend technology/version",
	"X-XSS-Protection":          "Outdated and potentially dangerous",
	"Public-Key-Pins":           "Obsolete (HKPK), replaced by certs",
	"X-AspNet-Version":          "Leaks ASP.NET version",
	"X-Generator":               "Leaks Wordpress or CMS version",
	"Server":                    "Leaks web server type and version",
	"X-PHP-Version":             "Leaks PHP version",
}

var mustHeaders = []string{
	"Content-Security-Policy",
	"X-Frame-Options",
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"Referrer-Policy",
	"Permission-Policy",
}

var shouldnot = []string{
	"X-Powered-By",
	"X-XSS-Protection",
	"Public-Key-Pins",
	"X-AspNet-Version",
	"X-Generator",
	"X-PHP-Version",
	"Server",
}

var headersignatures = map[string]string{
	"cf-ray":               "Cloudflare",
	"x-amzn-waf":           "AWS WAF",
	"x-sucuri-id":          "Sucuri",
	"x-sucuri-cache":       "Sucuri",
	"x-iinfo":              "Incapsula (Imperva)",
	"x-cdn":                "Incapsula (Imperva)",
	"akamai-ghost":         "Akamai",
	"x-akamai-transformed": "Akamai",
	"x-fe-request-id":      "Fastly",
	"server: cloudflare":   "Cloudflare",
	"x-waf-event-info":     "F5 BIG-IP",
	"x-denied-reason":      "Barracuda WAF",
	"x-hw":                 "Huawei CLoud WAF",
	"x-waf-status":         "ModSecurity",
	"x-bespoke-waf":        "Bespoke/Custom WAF",
	"x-cache":              "Akamai/Varnish",
}

var cookiesignatures = map[string]string{
	"__cfduid":        "Cloudflare",
	"cf_clearance":    "Cloudflare",
	"incap_ses_":      "Incapsula (Imperva)",
	"visid_incap_":    "Incapsula (Imperva)",
	"ak_bmsc":         "Akamai",
	"bm_sv":           "Akamai",
	"f5_cspm":         "F5 BIG-IP",
	"BIGipServer":     "F5 BIG-IP",
	"citrix_ns_id":    "Citrix NetScaler",
	"ns_af":           "Citrix NetScaler",
	"TS01":            "F5 BIG-IP",
	"mod_security_id": "ModSecurity",
	"cookies_test":    "Cloudflare",
}

var cmssignatures = map[string]string{
	"wp-content":       "Wordpress",
	"wp-includes":      "Wordpress",
	"com_content":      "Joomla",
	"joomla-version":   "Joomla",
	"drupal.js":        "Drupal",
	"sites/all/themes": "Drupal",
	"typo3":            "TYPO3",
	"moodle":           "Moodle",
	"cdn.shopify.com":  "Shopify",
	"skinfrontend/":    "Magento",
	"prestashop":       "PrestaShop",
	"wix.com":          "Wix",
	"blogger.com":      "Blogger",
}

func detectWAFHeaders(resp *http.Response) string {
	for name, values := range resp.Header {
		lowerName := strings.ToLower(name)
		if waf, ok := headersignatures[lowerName]; ok {
			return waf
		}
		for _, val := range values {
			keyVal := lowerName + ": " + strings.ToLower(val)
			if waf, ok := headersignatures[keyVal]; ok {
				return waf
			}
		}
	}
	return ""
}

func detectWAFCookies(resp *http.Response) string {
	for _, cookie := range resp.Cookies() {
		for sig, waf := range cookiesignatures {
			if strings.Contains(cookie.Name, sig) {
				return waf
			}
		}
	}
	return ""
}

func detectCMS(resp *http.Response) string {
	bodyBytes := make([]byte, 16384)
	n, _ := resp.Body.Read(bodyBytes)
	bodyContent := string(bodyBytes[:n])
	if resp.Header.Get("X-ShopId") != "" || resp.Header.Get("X-Shopify-Shop-Api-Public-Token") != "" {
		return "Shopify"
	}
	for _, cookie := range resp.Cookies() {
		if strings.HasPrefix(cookie.Name, "_shopify_") {
			return "Shopify"
		}
	}
	for pattern, cmsName := range cmssignatures {
		if strings.Contains(bodyContent, pattern) {
			return cmsName
		}
	}
	return "N/A"
}

func main() {
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	purple := color.New(color.FgMagenta).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()

	target := flag.String("d", "", "Target Domain (ex. example.com)")
	cmsDetect := flag.Bool("cms", false, "Enable CMS Detection")
	flag.Usage = func() {
		fmt.Printf("[ Webrr ]\n")
		fmt.Printf("Usage: webrr -d example.com")
		fmt.Println("\n\nOptions:")
		fmt.Println("  -d      Target Domain (ex. example.com)")
		fmt.Println("  --cms   Enable CMS Detection")
	}
	flag.Parse()

	if *target == "" {
		flag.Usage()
		return
	}

	finalUrl := *target
	lowerUrl := strings.ToLower(finalUrl)
	if !strings.HasPrefix(lowerUrl, "http://") && !strings.HasPrefix(lowerUrl, "https://") {

		if strings.Contains(lowerUrl, "localhost") ||
			strings.Contains(lowerUrl, "127.0.0.1") ||
			strings.HasPrefix(lowerUrl, "192.168.") ||
			strings.HasSuffix(lowerUrl, ".local") ||
			strings.HasPrefix(lowerUrl, "10.") ||
			strings.HasPrefix(lowerUrl, "172.16.") ||
			strings.HasPrefix(lowerUrl, "172.17.") ||
			strings.HasPrefix(lowerUrl, "172.31.1") {
			finalUrl = "http://" + finalUrl
		} else {
			finalUrl = "https://" + finalUrl
		}
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(finalUrl)
	if err != nil {
		fmt.Printf("[%s] Error while connecting: %v\n", red("x"), err)
		return
	}
	defer resp.Body.Close()
	serverType := resp.Header.Get("Server")
	if serverType == "" {
		serverType = "Unknown"
	}
	detectedWAF := detectWAFHeaders(resp)
	if detectedWAF == "" {
		detectedWAF = detectWAFCookies(resp)
	}
	if detectedWAF == "" {
		detectedWAF = "N/A"
	}
	banner := `
 █     █░▓█████  ▄▄▄▄    ██▀███   ██▀███  
▓█░ █ ░█░▓█   ▀ ▓█████▄ ▓██ ▒ ██▒▓██ ▒ ██▒
▒█░ █ ░█ ▒███   ▒██▒ ▄██▓██ ░▄█ ▒▓██ ░▄█ ▒
░█░ █ ░█ ▒▓█  ▄ ▒██░█▀  ▒██▀▀█▄  ▒██▀▀█▄  
░░██▒██▓ ░▒████▒░▓█  ▀█▓░██▓ ▒██▒░██▓ ▒██▒
░ ▓░▒ ▒  ░░ ▒░ ░░▒▓███▀▒░ ▒▓ ░▒▓░░ ▒▓ ░▒▓░
  ▒ ░ ░   ░ ░  ░▒░▒   ░   ░▒ ░ ▒░  ░▒ ░ ▒░		github.com/wpxq
  ░   ░     ░    ░    ░   ░░   ░   ░░   ░ 
    ░       ░  ░ ░         ░        ░     
                      ░                   
	`
	fmt.Println(banner)
	fmt.Printf("[%s] Target: %s\n", purple("W"), *target)
	fmt.Printf("[%s] Server: %s\n", purple("W"), serverType)
	fmt.Printf("[%s] WAF: %s\n", purple("W"), detectedWAF)
	if *cmsDetect {
		cms := detectCMS(resp)
		fmt.Printf("[%s] CMS: %s\n", purple("W"), cms)
	}
	fmt.Println()

	fmt.Printf("[%s] Checking for missing or mandatory headers\n", purple("W"))
	for _, header := range mustHeaders {
		val := resp.Header.Get(header)
		if val == "" {
			fmt.Printf("[%s] Missing: %-25s | [%s]\n", yellow("!"), header, headersRisks[header])
		} else {
			fmt.Printf("[%s] Set:     %-25s | [%s]\n", green("+"), header, val)
		}
	}
	fmt.Printf("\n[%s] Checking for missing or unwanted headers\n", purple("W"))
	for _, header := range shouldnot {
		val := resp.Header.Get(header)
		if val == "" {
			fmt.Printf("[%s] Not set (Safe): %-25s\n", green("+"), header)
		} else {
			fmt.Printf("[%s] Unwanted: %-25s | [%s] | [%s]\n", yellow("!"), header, val, headersRisks[header])
		}
	}
}
