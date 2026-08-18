# Webrr

![webrr](https://github.com/wxwreak/webrr/blob/main/webrr-showcase.png)

---

Webrr is a command-line utility written in Go designed to perform reconnaissance on web servers. It checks for security-related HTTP headers, detects Web Application Firewalls (WAFs), and identifies Content Management Systems (CMS)

---

## Features
- **Security Header Analysis:** Checks for mandatory security headers and alert if inscure/unwanted headers are present.
- **WAF Detection:** Identifies pontetial WAF presence via response headers and cookies.
- **CMS Detection:** Scans response contet and headers to identify the underlying CMS [optional].
- **Detailed Reporting:** Provides a clear status of server configuration security.

## Requirements
- Go 26.4
- `fatih/color`

## Setup
1. Clone this repo:
2. Build the project using the provided Makefile:
```bash
make
```

## Usage
Basic usage:
```bash
webrr -d example.com
```
Enable CMS detection:
```bash
webrr -d example.com --cms
```

## Options
- `-d`: Specify the target domain (e.g. example.com)
- `--cms`: Enable detection of the target's CMS.

## Security Header Definitons
The tool evaluates headers againts two categories:

## **Mandatory Headers**
These headers are checked for their presence to ensure basic security posture:
- **Content-Security-Policy**
- **X-Frame-Options**
- **Strict-Transport-Security**
- **X-Content-Type-Options**
- **Referrer-Policy**
- **Permission-Policy**

## **Unwanted Headers**
These headers are checked to ensure they are NOT present, as they often leak sensitive
backend technology information or are considered outdated:
- **X-Powered-By**
- **X-XSS-Protection**
- **Public-Key-Pins**
- **X-AspNet-Version**
- **X-Generator**
- **X-PHP-Version**
- **Server**
