# Passive Automated Lead Profiler Tool
# Main script

import re

def extract_domain(input_string: str) -> str | None:
    """
    Extracts the domain from an input string (domain or email).
    Returns the domain name or None if extraction fails.
    """
    if not input_string:
        return None

    # Remove http(s):// prefix
    input_string = re.sub(r'^https?://', '', input_string.strip())
    # Remove www. prefix
    input_string = re.sub(r'^www\.', '', input_string)
    # Remove path and query parameters
    input_string = input_string.split('/')[0]
    input_string = input_string.split('?')[0]

    # Regex to validate a domain name (simplified, allows IDNs with xn-- prefix)
    # It checks for typical domain structure: labels separated by dots,
    # with the TLD being at least 2 characters long.
    # Labels can include alphanumeric characters, hyphens, and 'xn--' for IDNs.
    domain_regex = re.compile(
        r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*([A-Za-z]{2,6}|xn--[A-Za-z0-9]{1,59})$'
    )
    # More refined regex for local part of email, then @, then domain_regex
    # This regex is a common one, but email validation can be very complex.
    # We are primarily interested in extracting a valid-looking domain.
    email_regex = re.compile(
        r"^[a-zA-Z0-9!#$%&'*+\-/=?^_`{|}~.]+@"  # Local part
        r"((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)*([A-Za-z]{2,6}|xn--[A-Za-z0-9]{1,59})$" # Domain part
    )

    # Check if it's an email address
    if '@' in input_string:
        match = email_regex.fullmatch(input_string)
        if match:
            # Extract the domain part from the email
            # The input_string here is already cleaned of http/www/paths
            domain_part = input_string.split('@')[1]
            # Validate the extracted domain part again, just in case,
            # though the email_regex should cover it.
            if domain_regex.fullmatch(domain_part):
                return domain_part
            else:
                # This case should ideally not be hit if email_regex is good
                return None
        else:
            # Check if it's a malformed email like "@example.com"
            if input_string.startswith('@'):
                 potential_domain = input_string[1:]
                 if domain_regex.fullmatch(potential_domain):
                     return potential_domain # Or decide to return None for such cases
                 else:
                     return None
            return None # Not a valid email format
    else:
        # Assume it's a domain, validate it
        if domain_regex.fullmatch(input_string):
            return input_string
        else:
            return None # Invalid domain format

import whois
from datetime import datetime

def get_whois_info(domain: str) -> dict:
    """
    Fetches WHOIS information for a given domain.
    Returns a dictionary with registrar, creation date, expiration date, and domain age.
    """
    results = {
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_years": None,
        "domain_age_months_remainder": None, # Months part of age after full years
        "error": None
    }
    try:
        w = whois.whois(domain)

        if w.status == 'invalid': # python-whois specific status for invalid domain
             results["error"] = f"WHOIS lookup failed: Invalid domain {domain}"
             return results
        if not w.registrar and not w.creation_date and not w.expiration_date:
            # This check is to see if we got any meaningful data.
            # Some TLDs might not return all fields or might be restricted.
            # The python-whois library might return an object with many None fields
            # if the lookup broadly fails or the TLD is not well supported.
            possible_reason = ""
            if hasattr(w, 'text') and w.text: # often the raw response has clues
                if "limit exceeded" in w.text.lower() or "rate limited" in w.text.lower():
                    possible_reason = "Rate limit possibly exceeded."
                elif "not found" in w.text.lower() or "no match" in w.text.lower():
                    possible_reason = f"Domain {domain} not found or no WHOIS record."
                else:
                    possible_reason = "WHOIS data incomplete or unavailable for this TLD."
            else:
                possible_reason = f"WHOIS data not found or incomplete for {domain}."
            results["error"] = possible_reason
            return results


        results["registrar"] = w.registrar

        # Handle cases where dates might be a list (take the first one) or a single datetime
        if isinstance(w.creation_date, list):
            results["creation_date"] = w.creation_date[0] if w.creation_date else None
        else:
            results["creation_date"] = w.creation_date

        if isinstance(w.expiration_date, list):
            results["expiration_date"] = w.expiration_date[0] if w.expiration_date else None
        else:
            results["expiration_date"] = w.expiration_date

        if results["creation_date"]:
            # Ensure creation_date is datetime object for comparison
            if not isinstance(results["creation_date"], datetime):
                # Attempt to parse if it's a string (though python-whois usually returns datetime)
                 results["error"] = "WHOIS creation date is not a valid datetime object."
                 return results # Or handle parsing if necessary

            now = datetime.now()
            age_delta = now - results["creation_date"]

            total_days = age_delta.days
            results["domain_age_years"] = total_days // 365
            # Approximate months for the remainder
            results["domain_age_months_remainder"] = (total_days % 365) // 30

            # Convert datetime objects to string for easier serialization later
            results["creation_date"] = results["creation_date"].isoformat() if results["creation_date"] else None

        if results["expiration_date"]:
            if not isinstance(results["expiration_date"], datetime) and results["expiration_date"] is not None:
                 results["error"] = "WHOIS expiration date is not a valid datetime object."
                 # Potentially try to parse, but for now, flag error
            else:
                results["expiration_date"] = results["expiration_date"].isoformat() if results["expiration_date"] else None


    except whois.parser.PywhoisError as e: # More specific exception for python-whois parsing issues
        results["error"] = f"WHOIS lookup failed for {domain}: {e}"
    except Exception as e:
        results["error"] = f"An unexpected error occurred during WHOIS lookup for {domain}: {e}"

    return results

import ssl
import socket
from datetime import datetime as dt, timezone # Alias dt, import timezone

def get_ssl_info(domain: str, port: int = 443) -> dict:
    """
    Checks SSL certificate for a given domain.
    Returns a dictionary with SSL status, expiry date, issuer, CN, and SANs.
    """
    results = {
        "ssl_enabled": False,
        "is_valid": None, # True if valid, False if expired/hostname mismatch, None if not checked/error
        "expiry_date": None,
        "issuer": None,
        "common_name": None,
        "subject_alt_names": [],
        "error": None
    }

    context = ssl.create_default_context()
    # Don't check hostname here, we'll do it manually after getting the cert
    # to provide more specific feedback if it's a mismatch.
    # context.check_hostname = False
    # context.verify_mode = ssl.CERT_NONE # Also not this, we want default verification for is_valid

    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                results["ssl_enabled"] = True

                # Issuer
                issuer_parts = dict(x[0] for x in cert.get('issuer', []))
                results["issuer"] = issuer_parts.get('organizationName', issuer_parts.get('commonName', 'N/A'))

                # Expiry Date
                if 'notAfter' in cert:
                    expiry_str = cert['notAfter']
                    # SSL module returns date in format: "Month Day HH:MM:SS YYYY GMT"
                    try:
                        # Parse the expiry string.
                        expiry_dt_naive = dt.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')

                        # Assume the parsed date is UTC if it's naive.
                        # The '%Z' format specifier handles 'GMT' by setting tzinfo to a UTC-like object.
                        # So, expiry_dt_naive might already be offset-aware.
                        if expiry_dt_naive.tzinfo is None or expiry_dt_naive.tzinfo.utcoffset(expiry_dt_naive) is None:
                            # If it's still naive or tzinfo is there but not specific enough (e.g. tzlocal()),
                            # explicitly set it to UTC.
                            expiry_dt_aware = expiry_dt_naive.replace(tzinfo=timezone.utc)
                        else:
                            # It's already timezone-aware, likely correctly parsed as GMT/UTC.
                            expiry_dt_aware = expiry_dt_naive

                        results["expiry_date"] = expiry_dt_aware.isoformat()

                        # Compare with current UTC time.
                        if expiry_dt_aware < dt.now(timezone.utc):
                            results["is_valid"] = False # Expired
                            results["error"] = results.get("error", "") + "Certificate has expired. "
                        # else, validity regarding expiry is fine. Other checks will follow.
                    except ValueError:
                        results["error"] = results.get("error", "") + f"Could not parse expiry date: {expiry_str}. "
                        results["is_valid"] = False # Cannot determine validity if date is unparsable

                # Common Name (CN) and Subject Alternative Names (SANs)
                subject_parts = dict(x[0] for x in cert.get('subject', []))
                results["common_name"] = subject_parts.get('commonName')

                sans = []
                if 'subjectAltName' in cert:
                    for type, value in cert['subjectAltName']:
                        sans.append(value)
                results["subject_alt_names"] = sans

                # Check hostname validity against CN and SANs
                # ssl.match_hostname requires the cert in a different format, so we do a manual check.
                # Python's default context.wrap_socket with server_hostname already does this check.
                # If it failed, it would have raised ssl.SSLCertVerificationError.
                # So, if we reach here without that error, hostname should be okay.
                # However, we can explicitly check if `is_valid` isn't already False.
                if results["is_valid"] is None: # If not already marked invalid (e.g. by expiry)
                    try:
                        # This is the critical check that context.wrap_socket performs if check_hostname is True (default)
                        # If an SSLCertVerificationError (base class for hostname mismatch, expiry etc.)
                        # was not raised by wrap_socket, the cert is generally considered valid by Python's SSL lib
                        # for that server_hostname.
                        results["is_valid"] = True
                    except ssl.SSLCertVerificationError as e: # Should have been caught by wrap_socket
                        results["is_valid"] = False
                        results["error"] = results.get("error", "") + f"Certificate hostname mismatch or other verification issue: {e}. "


    except ssl.SSLCertVerificationError as e:
        results["ssl_enabled"] = True # SSL is enabled, but cert is not valid
        results["is_valid"] = False
        results["error"] = f"SSL certificate verification failed: {e.strerror} (Code: {e.verify_code}, Message: {e.verify_message})"
        # Try to get cert details even if verification fails for partial info
        try:
            cert = ssl.get_server_certificate((domain, port))
            # This is just a PEM string, to get details you'd need to parse it.
            # For simplicity, if main verification fails, we'll rely on the error message.
            # Parsing it would require cryptography library or similar.
        except Exception:
            pass # Can't get cert if connection fully fails before cert exchange
    except ssl.SSLError as e:
        # This can be various SSL issues, e.g., no common protocols, handshake failure
        results["error"] = f"An SSL error occurred: {e}"
    except socket.timeout:
        results["error"] = f"Connection timed out while trying to connect to {domain} on port {port}."
    except socket.gaierror:
        results["error"] = f"Could not resolve hostname: {domain}."
    except ConnectionRefusedError:
        results["error"] = f"Connection refused by {domain} on port {port}."
    except Exception as e:
        results["error"] = f"An unexpected error occurred during SSL check for {domain}: {e}"

    return results

# Placeholder for VirusTotal API Key
VIRUSTOTAL_API_KEY = None # Needs to be set by the user

def get_virustotal_info(domain: str, api_key: str | None) -> dict:
    """
    Fetches domain reputation from VirusTotal API v3.
    Placeholder function.
    """
    results = {
        "detection_ratio": None,
        "malicious_categories": [],
        "detection_reasons": [],
        "error": None
    }

    if not api_key:
        results["error"] = "VirusTotal API key not provided."
        # Optionally, could print a message to the user here or log it.
        # For now, just returning the error in the results.
        print("Warning: VirusTotal API key not configured. Skipping VirusTotal check.")
        return results

    # Actual implementation will involve:
    # 1. Constructing the API URL for domain reports:
    #    API_ENDPOINT = f"https://www.virustotal.com/api/v3/domains/{domain}"
    # 2. Setting up headers with "x-apikey": api_key
    # 3. Making a GET request using the 'requests' library.
    # 4. Parsing the JSON response.
    #    - response.json()['data']['attributes']['last_analysis_stats'] for detection_ratio (e.g. malicious, suspicious)
    #    - response.json()['data']['attributes']['categories'] or 'tags' for malicious categories
    #    - response.json()['data']['attributes']['last_analysis_results'] for detection reasons by AV engines
    # 5. Handling API errors (rate limits, not found, invalid key).

    results["error"] = "VirusTotal integration not fully implemented yet."
    # Simulating a successful call for structure, replace with actual API call
    # results["detection_ratio"] = "0/91"
    # results["malicious_categories"] = ["harmless"]

    return results

import requests

def get_server_info(domain: str) -> dict:
    """
    Fetches basic server information (Server header) using HTTP GET request.
    """
    results = {
        "server_header": None,
        "error": None
    }

    protocols = ["https", "http"]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    for protocol in protocols:
        url = f"{protocol}://{domain}"
        try:
            response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
            # Check for a successful response (2xx) before proceeding
            # Some servers might return an error page with a Server header, which is fine.
            # If a redirect occurs, requests.get handles it and response.url will be the final URL.

            results["server_header"] = response.headers.get("Server")
            if results["server_header"]:
                results["error"] = None # Clear any previous error if successful with this protocol
                return results # Found server header, no need to check other protocol
            else:
                # No server header, but connection was successful.
                # This is not an error, but we might want to note it.
                # Fall through to try http if https yielded no server header.
                 results["error"] = f"No 'Server' header found at {url} (status code: {response.status_code})."

        except requests.exceptions.SSLError as e:
            results["error"] = f"SSL error connecting to {url}: {e}. Trying HTTP."
            # Continue to try HTTP if HTTPS fails with SSL error
            continue
        except requests.exceptions.ConnectionError as e:
            results["error"] = f"Connection error for {url}: {e}"
            # If https fails with connection error, http might still work or also fail.
            # Let it try the next protocol. If both fail, the last error will be reported.
            continue
        except requests.exceptions.Timeout:
            results["error"] = f"Request timed out for {url}."
            continue
        except requests.exceptions.RequestException as e:
            results["error"] = f"An error occurred for {url}: {e}"
            # For other request exceptions, also try the next protocol.
            continue

    # If loop finishes, it means either no server header was found or all attempts failed.
    # The last error encountered will be in results["error"] if all attempts failed.
    # If one attempt succeeded but found no server header, that specific message will be there.
    return results

def get_seo_index_visibility(domain: str) -> dict:
    """
    Placeholder for checking SEO index visibility (e.g., site:domain.com query).
    Actual implementation is complex due to anti-scraping measures by search engines.
    """
    results = {
        "estimated_indexed_pages": None,
        "status_notes": "Manual check recommended for SEO index visibility.",
        "error": "Feature not fully implemented. Relies on manual checks or future integration with a search API."
    }

    # Potential future approach (if a reliable, ToS-compliant method is found):
    # 1. Use a library like 'googlesearch-python' (unofficial, use with caution regarding ToS)
    #    or 'duckduckpy' (for DuckDuckGo, potentially more lenient but less comprehensive).
    # 2. Perform a "site:{domain}" query.
    # 3. Try to parse the number of results. This is highly fragile.
    # 4. Note: Public search engine APIs (like Google's Custom Search JSON API) often have costs
    #    and daily limits, and might not perfectly replicate organic 'site:' query counts.

    print(f"SEO Index Visibility for {domain}: {results['status_notes']} {results['error']}")
    return results

def get_security_headers_info(domain: str) -> dict:
    """
    Analyzes the presence or absence of common security headers.
    Checks: Content-Security-Policy, Strict-Transport-Security,
            X-Frame-Options, X-XSS-Protection.
    """
    results = {
        "headers_present": {}, # Stores actual values if present
        "headers_missing": [],
        "error": None
    }

    security_headers_to_check = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-XSS-Protection",
        # "X-Content-Type-Options", # Also common, consider adding
        # "Referrer-Policy",         # Also common
        # "Permissions-Policy"       # Newer, replacing Feature-Policy
    ]

    protocols = ["https", "http"]
    user_agent_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    final_url_checked = None

    for protocol in protocols:
        url = f"{protocol}://{domain}"
        try:
            # Using HEAD request first to save bandwidth, fallback to GET if needed or preferred.
            # Some servers might not respond accurately to HEAD for all headers, GET is more robust.
            # For simplicity here, let's use GET as it's generally more reliable for full header sets.
            response = requests.get(url, headers=user_agent_headers, timeout=5, allow_redirects=True)
            final_url_checked = response.url # URL after redirects

            for header in security_headers_to_check:
                if header in response.headers:
                    results["headers_present"][header] = response.headers[header]
                else:
                    results["headers_missing"].append(header)

            # If we got a response from HTTPS, we generally prefer it.
            # No need to check HTTP if HTTPS was successful.
            if protocol == "https" and not results["error"]:
                 results["checked_url"] = final_url_checked
                 return results

        except requests.exceptions.SSLError as e:
            results["error"] = f"SSL error for {url}: {e}. Trying HTTP if available."
            # Continue to try HTTP
        except requests.exceptions.ConnectionError as e:
            results["error"] = f"Connection error for {url}: {e}"
            # Continue, maybe HTTP works
        except requests.exceptions.Timeout:
            results["error"] = f"Request timed out for {url}."
            # Continue
        except requests.exceptions.RequestException as e:
            results["error"] = f"Generic error for {url}: {e}"
            # Continue

        # If we are here after trying HTTPS and it failed, and now trying HTTP
        # we should clear missing headers from the HTTPS attempt if it populated any error
        # and then re-evaluate based on HTTP.
        # However, the current logic will overwrite if HTTP succeeds.
        # If HTTPS fails and then HTTP fails, the last error is kept.
        # If HTTPS succeeds, it returns. If HTTPS fails and HTTP succeeds, it returns.

    results["checked_url"] = final_url_checked if final_url_checked else domain
    # If loop completes, it means either only HTTP was tried (and results are from it),
    # or HTTPS failed and HTTP was tried (results from HTTP),
    # or both failed (last error is kept).
    return results

def get_robots_txt_info(domain: str) -> dict:
    """
    Checks for robots.txt, its content, and highlights disallow rules.
    """
    results = {
        "robots_txt_exists": False,
        "robots_txt_url": None,
        "disallow_rules": [],
        "sitemap_directives": [],
        "other_directives": [], # For User-agent, Allow, Crawl-delay etc.
        "content_preview": None, # First few lines
        "error": None
    }

    protocols = ["https", "http"]
    user_agent_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }


    # Order of preference: https://www, https://, http://www, http://
    # Some sites might only have robots.txt on www, others on non-www.
    # Some might redirect http to https.
    base_urls_to_try = [
        f"https://www.{domain}",
        f"https://{domain}",
        f"http://www.{domain}",
        f"http://{domain}"
    ]

    last_error = None

    for base_url in base_urls_to_try:
        current_robots_url = f"{base_url}/robots.txt"
        try:
            response = requests.get(current_robots_url, headers=user_agent_headers, timeout=7, allow_redirects=True) # Allow redirects
            results["robots_txt_url"] = response.url # Store the final URL

            # Check if the final URL still looks like a robots.txt path and status is OK
            if response.status_code == 200 and response.url.endswith("/robots.txt"):
                results["robots_txt_exists"] = True
                content = response.text
                lines = content.splitlines()
                results["content_preview"] = "\n".join(lines[:10])
                # Clear previous attempt's parsed data if any
                results["disallow_rules"] = []
                results["sitemap_directives"] = []
                results["other_directives"] = []

                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"): continue
                    if line.lower().startswith("disallow:"): results["disallow_rules"].append(line)
                    elif line.lower().startswith("sitemap:"): results["sitemap_directives"].append(line)
                    elif any(line.lower().startswith(p) for p in ["user-agent:", "allow:", "crawl-delay:"]):
                        results["other_directives"].append(line)

                results["error"] = None
                return results # Successfully processed robots.txt

            elif response.status_code == 404:
                last_error = f"robots.txt not found at {current_robots_url} (final URL: {response.url}, status 404)."
            elif response.url.endswith("/robots.txt"): # Got a non-200/404 status for a robots.txt URL
                 last_error = f"Unexpected status {response.status_code} for {current_robots_url} (final URL: {response.url})."
            else: # Redirected to something not ending in /robots.txt
                last_error = f"Request for {current_robots_url} redirected to a non-robots.txt URL: {response.url} (status {response.status_code})."

        except requests.exceptions.SSLError as e:
            last_error = f"SSL error for {current_robots_url}: {e}."
        except requests.exceptions.ConnectionError as e:
            last_error = f"Connection error for {current_robots_url}: {e}."
        except requests.exceptions.Timeout:
            last_error = f"Request timed out for {current_robots_url}."
        except requests.exceptions.RequestException as e:
            last_error = f"Generic error for {current_robots_url}: {e}."

        results["error"] = last_error # Store the error from this attempt before trying next

    # If loop completes, all attempts failed. The last error is in results["error"].
    return results

import dns.resolver
import dns.exception

def get_dns_records_info(domain: str) -> dict:
    """
    Extracts A, NS, and MX DNS records for a given domain.
    """
    results = {
        "a_records": [],
        "ns_records": [],
        "mx_records": [],
        "error": None
    }

    record_types = ["A", "NS", "MX"]
    errors = []

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                if rtype == "A":
                    results["a_records"].append(rdata.address)
                elif rtype == "NS":
                    results["ns_records"].append(rdata.target.to_text(omit_final_dot=True))
                elif rtype == "MX":
                    results["mx_records"].append({
                        "preference": rdata.preference,
                        "exchange": rdata.exchange.to_text(omit_final_dot=True)
                    })
        except dns.resolver.NoAnswer:
            # No records of this specific type, not necessarily an error for the whole process
            # print(f"No {rtype} records found for {domain}.")
            pass
        except dns.resolver.NXDOMAIN:
            errors.append(f"Domain {domain} does not exist (NXDOMAIN).")
            # If domain doesn't exist, no point trying other record types
            results["error"] = ", ".join(errors)
            return results
        except dns.exception.Timeout:
            errors.append(f"DNS query for {rtype} records timed out for {domain}.")
        except dns.resolver.NoNameservers:
             errors.append(f"No nameservers available for {rtype} query for {domain}.")
        except Exception as e:
            errors.append(f"Error fetching {rtype} records for {domain}: {e}")

    if errors:
        results["error"] = "; ".join(errors)

    # Sort records for consistent output, especially MX by preference
    results["a_records"].sort()
    results["ns_records"].sort()
    if results["mx_records"]:
        results["mx_records"].sort(key=lambda x: x["preference"])

    return results

import argparse
import json # For pretty printing the dict

# Remember to set this or use env var / config file in actual VirusTotal implementation
# For now, it's passed to the function.
USER_VIRUSTOTAL_API_KEY = None

def run_domain_profile(domain_input: str) -> dict:
    """
    Runs all profiling functions for a single domain input and aggregates results.
    """
    master_results = {"input": domain_input, "domain": None, "profile_data": {}, "errors": []}

    parsed_domain = extract_domain(domain_input)
    if not parsed_domain:
        master_results["errors"].append(f"Could not parse a valid domain from input: {domain_input}")
        # Even if domain parsing fails, some info might be relevant if it was an email,
        # but for now, we stop if no valid domain is found.
        return master_results

    master_results["domain"] = parsed_domain
    domain = parsed_domain # Use 'domain' for clarity in calls below

    print(f"\n--- Profiling Domain: {domain} ---")

    # 1. WHOIS Info
    print("Fetching WHOIS info...")
    whois_data = get_whois_info(domain)
    master_results["profile_data"]["whois"] = whois_data
    if whois_data.get("error"):
        master_results["errors"].append(f"WHOIS Error: {whois_data['error']}")

    # 2. SSL Info
    print("Fetching SSL certificate info...")
    ssl_data = get_ssl_info(domain)
    master_results["profile_data"]["ssl"] = ssl_data
    if ssl_data.get("error") and not ssl_data.get("ssl_enabled"): # Report error only if SSL not enabled or true error
        master_results["errors"].append(f"SSL Error: {ssl_data['error']}")

    # 3. VirusTotal Info (Placeholder)
    print("Fetching VirusTotal info (placeholder)...")
    # Decision: How to get API key here? For now, use global or pass if available.
    # This will be refined when VT is fully implemented.
    vt_data = get_virustotal_info(domain, USER_VIRUSTOTAL_API_KEY)
    master_results["profile_data"]["virustotal"] = vt_data
    if vt_data.get("error"):
         # Don't add "API key not provided" or "not implemented" to general errors unless verbose mode
        if "API key not provided" not in vt_data["error"] and "not fully implemented" not in vt_data["error"]:
            master_results["errors"].append(f"VirusTotal Error: {vt_data['error']}")

    # 4. Server Info (Basic Tech Stack)
    print("Fetching Server info...")
    server_data = get_server_info(domain)
    master_results["profile_data"]["server_info"] = server_data
    if server_data.get("error") and not server_data.get("server_header"): # If no header but no conn error, it's not a "tool" error
         master_results["errors"].append(f"Server Info Error: {server_data['error']}")

    # 5. SEO Index Visibility (Placeholder)
    print("Fetching SEO Index Visibility (placeholder)...")
    seo_data = get_seo_index_visibility(domain) # This function currently prints its own status
    master_results["profile_data"]["seo_visibility"] = seo_data
    # Error already handled by the function's print for now

    # 6. Security Headers
    print("Fetching Security Headers info...")
    sec_headers_data = get_security_headers_info(domain)
    master_results["profile_data"]["security_headers"] = sec_headers_data
    if sec_headers_data.get("error"): # e.g. connection errors
        master_results["errors"].append(f"Security Headers Error: {sec_headers_data['error']}")

    # 7. robots.txt Info
    print("Fetching robots.txt info...")
    robots_data = get_robots_txt_info(domain)
    master_results["profile_data"]["robots_txt"] = robots_data
    # Report error only if robots.txt doesn't exist AND there was an actual connection/processing error
    if not robots_data.get("robots_txt_exists") and robots_data.get("error"):
         # Avoid reporting simple 404s as major errors unless verbose.
         if "404" not in robots_data.get("error"): # Suppress simple "not found"
            master_results["errors"].append(f"robots.txt Error: {robots_data['error']}")

    # 8. DNS Records
    print("Fetching DNS records...")
    dns_records_data = get_dns_records_info(domain)
    master_results["profile_data"]["dns_records"] = dns_records_data
    if dns_records_data.get("error"):
        master_results["errors"].append(f"DNS Records Error: {dns_records_data['error']}")

    return master_results


def main():
    parser = argparse.ArgumentParser(description="Passive Automated Lead Profiler Tool for Domain Reconnaissance.")
    parser.add_argument("domain_input", type=str, help="Single domain (e.g., example.com) or email (e.g., admin@example.com) to profile.")
    # Future arguments: -f for batch file, -o for output dir, --vt-key for VirusTotal API key etc.

    args = parser.parse_args()

    print(f"Lead Profiler Tool initialized for: {args.domain_input}")

    # Run the full profile
    profile_results = run_domain_profile(args.domain_input)

    # Pretty print the aggregated results
    print("\n\n--- Aggregated Profile Results ---")
    print(json.dumps(profile_results, indent=4))

    if profile_results["errors"]:
        print("\n--- Errors Encountered During Profiling ---")
        for err in profile_results["errors"]:
            print(f"- {err}")

    # --- Previous Test Sections (now part of run_domain_profile or CLI driven) ---
    # ... (test_domains_for_dns, etc.) ...

    # print("\n--- Testing domain extraction (Commented out) ---")
    # inputs = [
    #     "example.com", "admin@example.com", "http://example.com",
    #     "https://www.example.com/path?query=1", "test@sub.example.co.uk",
    #     "www.example.com", "invalid-email@", "@invalid.com", "example",
    #     "http://localhost", "user@localhost", "xn--p8j9a0d9c.xn--q9jyb4c",
    #     "test@xn--p8j9a0d9c.xn--q9jyb4c"
    # ]
    # for item in inputs:
    #     print(f"Input: '{item}' -> Extracted Domain: '{extract_domain(item)}'")


if __name__ == "__main__":
    main()
