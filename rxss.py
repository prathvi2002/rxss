#!/usr/bin/python3

#* ============== Points to keep in mind while using pxss ==============
# always pass through proxy adding request headers for target urls
# maybe in mitmproxy request headers always include accept content type to html?

#* ============== Points to keep in mind while building or updating pxss ==============
#! never URL encode ? which starts the portion of query paramters in URL, or the server will treat parameters after ? as part of path rather then query paramters.
# do all searching case-insensitive
# request.get automatically url encodes the url while making request

#TODO: As this tool is only made to test response with content type of html, if the response content type header is json or any other content type then send the same request again with Accept REQUEST header value replaced to application/html like Accept: application/html, and then see if the response content type header is html. this will increase the attack surface. In github the endpoint was returning data type of json https://github.com/s0md3v/Arjun/commits/master/ but when i changed the Accept requset header value to application/html the response returned html instead of json.

#TODO Make this tool also test URL paths 3 level deep for unfiltered characters

#TODO: add try exceptions blocks so in case any error for a single url other urls provided in the input are tested without whole tool stopping

#TODO: if the response is not in 200 range then send the special character check payload again without url encoding only the PAYLOAD and check if this time the response code is in 200 range, if this response code is in 200 range then use this current response to detect unfilteterd special characeter. if the response is still not in 200 range then use the FIRST response to detect unfiltered special character.

#TODO: while checking for unfiltered special character even while url encoded payload if the first request fails, try the request using the same payload once more before giving up.

#TODO: if the special characters is not present (unfiltered) in response body then send the special character check payload again without url encoding only the PAYLOAD and check if this time the special character is present (unfiltered) in response

import sys  # Used to read from standard input (piped data).
import os
import requests  # For making HTTP GET requests.
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, unquote  # For safely parsing and reconstructing URLs and query strings.
import urllib3  # For handling SSL warning suppression
import argparse
import argcomplete
import threading
from urllib.parse import quote  # to URL-encode the URL
import subprocess
import shutil

from bs4 import BeautifulSoup
from pygments import highlight
from pygments.lexers import HtmlLexer
from pygments.formatters import TerminalFormatter

# Disable SSL certificate warnings 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ Global Variables ============


# # If --nocolour flag is passed via command line, then colour colour variabes won't make effect in code even if they are used
# if nocolour is True:
#     YELLOW = "\033[0m"
#     GRAY = "\033[0m"
#     GREEN = "\033[0m"
#     CYAN = "\033[0m"
#     PINK = "\033[0m"
#     RESET = "\033[0m"
# else:
#     # ANSI escape codes to color specific parts of printed output for visibility and categorization.
#     YELLOW = "\033[93m"
#     GRAY = "\033[90m"
#     GREEN = "\033[32m"
#     CYAN = "\033[96m"
#     PINK = "\033[95m"
#     RESET = "\033[0m"

terminal_width = shutil.get_terminal_size().columns

#! debug_print does NOT print regex results
# passing f-strings to debug_print function - this function can handle f-strings directly (e.g., debug_print(f"one plus one = {1+1}")) and f-strings in variables passed as f-strings (e.g., 1plus1 = f"one plus one = {1+1}"; debug_print(f"{1plus1}")), but not f-string variables directly (e.g., 1plus1 = f"one plus one = {1+1}"; debug_print(1plus1)).
def debug_print(message, newline=False):
    """If debug_mode is enabled, prints debug messages from wherever it is called.

    Args:
        message (str): The message to be printed. This can be a regular string or an f-string.
        newline (bool, optional): If True, prints message with formatting and a separator. Defaults to False.
    """
    if debug_mode and newline:
        cyan_line = f"{CYAN}{'-' * 150}{RESET}"
        print(f"\n\n{cyan_line}\nDebug: {message}{RESET}\n{cyan_line}")
    elif debug_mode:
        print(f"Debug: {message}")


def replace_empty_url_param(url, target_param, default_value="123"):
    """
    In the given URL, if `target_param` appears with no value (e.g. `param=` or just `param`) in either the semicolon‐embedded path or the query string (even if the URL forgot the '?'), fills it with default_value. Leaves every other parameter untouched, and preserves encoding.

    Args:
        url (str): The URL to process.
        target_param (str): The name of the parameter to fill if empty (case-sensitive).
        default_value (str): What to assign if the parameter has no value.

    Returns:
        str: The updated URL.
    """
    parsed = urlparse(url)

    # Handle missing '?' but '&' in path
    if not parsed.query and "&" in parsed.path:
        base, fake_q = parsed.path.split("&", 1)
        parsed = parsed._replace(path=base, query=fake_q)

    # Process query string
    new_query_parts = []
    for part in parsed.query.split("&"):
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            if key == target_param and val == "":
                new_query_parts.append(f"{key}={default_value}")
            else:
                new_query_parts.append(part)
        else:
            # “key” with no '='
            if part == target_param:
                new_query_parts.append(f"{part}={default_value}")
            else:
                new_query_parts.append(part)
    new_query = "&".join(new_query_parts)

    # Process semicolon‐embedded path params
    new_path_parts = []
    for part in parsed.params.split(";"):
        if not part:
            continue
        if "=" in part:
            key, val = part.split("=", 1)
            if key == target_param and val == "":
                new_path_parts.append(f"{key}={default_value}")
            else:
                new_path_parts.append(part)
        else:
            if part == target_param:
                new_path_parts.append(f"{part}={default_value}")
            else:
                new_path_parts.append(part)
    new_params = ";".join(new_path_parts)

    # Rebuild URL
    return urlunparse(parsed._replace(query=new_query, params=new_params))


# #! If a URL contains the same query parameter multiple times (e.g., price=1&price=2), the modified URL will only retain one instance of that parameter with the new value. For example: https://example.com/page?foo=bar&price=100&price=200 becomes: https://example.com/page?foo=bar&price=aprefixpriceapsuffix
# def modified_url_param(url, target_param, replace_value):
#     """Replaces the VALUE of a specific query or path-embedded parameter (specified using target_param) in the given URL (specified using url) with a new string (specified using replace_value).

#     Args:
#         url (str): The URL to modify: URL whose targeted query paramter value needs to be replaced with replace_value.
#         target_param (str): The name of the parameter to modify: Target query paramter name which will tell the function which query parameter's value needs to be replaced with replace_value.
#         replace_value (str): Value that should be replaced with the current parameter value.

#     Returns:
#         modified_url (str or None): URL with the updated target query or path-embedded parameter value specified with replace_value while preserving all other paramters. Returns None if the target parameter is not found in URL paramters.
#     """

#     # if isinstance(url, bytes):  # fix for byte-type URLs  (didn't fix any error)
#     #     url = url.decode('utf-8', errors='replace')

#     parsed = urlparse(url)  # Splits the URL into components (scheme, netloc, path, params [parameters embedded in the path], query parameters, and fragment).

#     # --- Handle query string ---
#     query_params = parse_qs(parsed.query, keep_blank_values=True)  # Parses the query string into a dict of lists. Example: ?name=alex&age=22 → { 'name': ['alex'], 'age': ['22'] }
#     query_modified = False  # Flag to track whether any query parameter was modified.

#     if target_param in query_params.keys():  # Check if the target parameter exists in the query parameter names.
#         query_params[target_param] = [replace_value]  # Replaces/modifies only the target query parameter value with replace_value. Other parameters are untouched.
#         query_modified = True  # Mark that a query param was successfully modified.


#     # --- Handle path-embedded parameters ---
#     # Path-embedded are parameters embedded in the path, which are part of the URL path segment, not the query string. semicolon (;) is used to define parameters for path segments. Example: https://example.com/path;param1=value1?query=123

#     path_modified = False  # Flag to track whether any path-embedded parameter was modified.
#     path_embedded_params = parsed.params.split(';')  # returns list of path-embedded parameters. e.g. ['param1=value1', 'param2=value2']
#     path_embedded_params = {k: [v] for k, v in (s.split('=', 1) for s in path_embedded_params if '=' in s)}  # Converts the embedded_params list into a dictionary with parameter values being a single itme list. Example: {'param_name': ['param_value'], 'param_name2': ['param_value2']}

#     if target_param in path_embedded_params.keys():  # Check if the target parameter exists in the path-embedded parameter names.
#         path_embedded_params[target_param] = [replace_value]  # Replaces/modifies only the target path-embedded parameter value with replace_value. Other parameters are untouched.
#         path_modified = True  # Mark that a path-embedded parameter was successfully modified.


#     # If neither the path nor the query was modified, there’s no point in rebuilding the URL.
#     if not query_modified and not path_modified:
#         return None  # Return None to indicate the target parameter wasn't found.


#     # If the target parameter was a query parameter then returns the url encoded modified URL by reconstructing the URL with the updated target query parameter value while preserving all other query paramters. 
#     if query_modified:
#         new_query = urlencode(query_params, doseq=True)
#         modified_url = urlunparse(parsed._replace(query=new_query))
#     # If the target parameter was a path-embedded parameter then returns the url encoded modified URL by reconstructing the URL with the updated target path-embedded parameter value while preserving all other path-embedded paramters. 
#     elif path_modified:
#         new_path_embedded = urlencode(path_embedded_params, doseq=True)
#         modified_url = urlunparse(parsed._replace(params=new_path_embedded))

#     return modified_url

#! If a URL contains the same path embedded parameter multiple times (e.g., price=1&price=2), the modified URL will only retain one instance of that parameter with the new value. For example: https://example.com/path;price=100&price=200?query=chips becomes: https://example.com/path;price=aprefixpriceapsuffix?query=chips
def modified_url_param(url, target_param, replace_value):
    """Replaces the VALUE of a specific query or path-embedded parameter (specified using target_param) in the given URL (specified using url) with a new string (specified using replace_value).

    Args:
        url (str): The URL to modify: URL whose targeted query paramter value needs to be replaced with replace_value.
        target_param (str): The name of the parameter to modify: Target query paramter name which will tell the function which query parameter's value needs to be replaced with replace_value.
        replace_value (str): Value that should be replaced with the current parameter value.

    Returns:
        modified_url (str or None): URL with the updated target query or path-embedded parameter value specified with replace_value while preserving all other paramters. Returns None if the target parameter is not found in URL paramters.
    """

    parsed = urlparse(url)
    found = False

    # --- Query string ---
    if parsed.query:
        parts = parsed.query.split("&")
        for i, part in enumerate(parts):
            if "=" in part:
                key, val = part.split("=", 1)
                if key == target_param:
                    parts[i] = f"{key}={replace_value}"
                    found = True
        new_query = "&".join(parts)
    else:
        new_query = ""

    # --- Path-embedded parameters ---
    if parsed.params:
        parts = parsed.params.split(";")
        for i, part in enumerate(parts):
            if "=" in part:
                key, val = part.split("=", 1)
                if key == target_param:
                    parts[i] = f"{key}={replace_value}"
                    found = True
        new_params = ";".join(parts)
    else:
        new_params = ""

    if not found:
        return None

    # Rebuild URL without touching any other characters
    return urlunparse(parsed._replace(query=new_query, params=new_params))


def detect_payload_reflection(url, target_param, payload, proxy_url):  #- Here proxy_url was proxy_url=None
    """If payload reflects in response body, returns the entire response body in one line with prefix 'Line 1: '.

    Args:
        url (str): URL for which reflection testing is to be done.
        target_param (str): Parameter name for which reflection is to be tested.
        payload (str): Payload which will be sent as paramter value to check for reflection.
        proxy_url (str, optional): Proxy through which requests has to be made. By default no proxy is used until passed in proxy_url.

    Returns:
        Tuple or None:
            - (response_body, response):
                - response_body (str or None): Entire response body with prefix 'Line 1: '.
                - response (<class 'requests.models.Response'>): Raw response of request containing everything from response headers to response body.
            - None:
                - Returns None if the target parameter is not present in URL parameters, if no reflection found in response body, if HTTP request fails (3xx, 4xx are NOT considered failed requests).
    """

    # Calls the modifier function so that we get a modified URL with target query or path-embedded paramter value in URL replaced with the value got in payload value (maybe always pass the payload in format aprefix<param>asuffix). Skips further steps if it fails.
    modified_url = modified_url_param(url, target_param=target_param, replace_value=payload)
    if modified_url is None:
        return None

    ###START Make a GET request to the modified URL. And checks for modified parameter value (payload) in response body. If payload is present in body then doesn't matter what the HTTP status code is, it stores it in response_body variable.
    # Makes a GET request to the modified URL. Timeout is 10 seconds. Through the proxy if supplied in cli argument. Without SSL verification.
    try:
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        response = requests.get(modified_url, timeout=10, proxies=proxies, verify=False, allow_redirects=False, headers=headers)
        # commented the below line coz Request without raise_for_status to allow 4xx/5xx body inspection to see if modified parameter value is present in response body or not.
        # response.raise_for_status()  # raises error for bad responses (4xx, 5xx).
    # Handles all request failures
    except Exception as e:
        debug_print(f"{YELLOW}[!] Request failed for {modified_url}: {e}{RESET}", newline=True)
        return None

    # skips if there is no payload (case-insensitive) reflection present in HTTP response body
    if payload.lower() not in response.text.lower():
        # if verbose is True:
        #     print(f"{GRAY}[-] No reflection found in response body. target paramter: {target_param}, payload: {payload}, url: {url}{RESET}")
        debug_print(f"{GRAY}[-] No reflection found in response body. target paramter: {target_param}, payload: {payload}, url: {url}{RESET}", newline=True)
        return None # Skip if payload is not reflected

    # stores entire response body with prefix 'Line 1: ' in one line (newlines removed).
    response_body = f"Line 1: {response.text.replace('\n', '')}"
    response_body = rf"{response_body}"
    ### END

    # debug_print(f"{GREEN}[+] Response body: {response_body}{RESET}", newline=True)
    return (response_body, response)


def unfiltered_characters_func(modified_url, target_param, proxy_url=None):  #- Here proxy_url was proxy_url=None
    """Checks for unfiltered special characters for a URL target parameter in a reflected HTML response.

    Args:
        url (str): The target URL.
        target_param (str): Paramter to inject payload into.
        proxy_url (str, optional): Proxy URL through which requests to make. Defaults to None.

    Returns:
        list or None:
            - None: Return None if no reflection found in response body, or target parameter is not present in URL parameters, or HTTP request fails (3xx, 4xx are NOT considered failed requests) for the URL. Or if Content-Type header is not found in response headers.
            - []: Returns an empty list if no special characters found to be unfiltered. Also sometimes when requests are failing.
            - list: Returns a list of unfiltered special characters if they are found.
    """

    first_try_fail = None  # declaring first_try_value variable with None value to avoid the error "cannot access local variable 'first_try_fail' where it is not associated with a value" which can occur if request succeeds in first request and 'if first_try_fail is True' statement is executed

    #* remember upon checking of Content-Type response header in response headers the response headers is lowercased
    ref_check_payload = f"aprefix{target_param}asuffix"

    # Send a request to check if the response Content-Type is HTML, retry once more if the first request fails.
    detected_payload_reflection = detect_payload_reflection(url=modified_url, target_param=target_param, payload=ref_check_payload, proxy_url=proxy_url)

    # On the first request, the request might fail coz of connection error, server error, or unexpected response; causing detect_payload_reflection() to return None. Since we can't unpack None into a tuple, we first check if the function returned a tuple value by checking if it didn't return None before attempting unpacking.
    if detected_payload_reflection is not None:
        response_body, raw_response = detected_payload_reflection
    else:
        debug_print(f"{YELLOW}[!] When checking for content type request failed{RESET}", newline=True)
        return None
        
    lower_raw_response_headers = dict(raw_response.headers.lower_items())  # dict containing each response header name and value, with header "names" in lowercase (header values remain original, their case is NOT changed).
    lower_raw_response_headers_name = list(lower_raw_response_headers.keys()) # list containing only response headers names

    #* use lowercase when checking for header names presence (using lowercased header names which are keys)
    # if Content-Type header is not present in response headers sets response_is_html to None
    if "content-type" not in lower_raw_response_headers_name:
        #TODO: when the Content-Type header is not present in response we aren't doing anything, do something about it to check for XSS. maybe still check for unfiltered characters and inform user in cli that Content-Type header wasn't present in response
        debug_print(f"{GRAY}[-] No Content-Type header present in response headers for URL {modified_url}", newline=True)
        response_is_html = None
    # if Content-Type header is present in response headers and its value is HTML type sets response_is_html True, otherwise False
    else:
        lower_content_type = lower_raw_response_headers.get('content-type').lower()  # contains Content-Type response header "value" in lowercase
        # if response content type is HTML set response_is_html to True
        if "html" in lower_content_type:
            response_is_html = True
        # if response content type is not HTML set response_is_html to True
        else:
            response_is_html = False


    if response_is_html is None:
        #TODO: when the Content-Type header is not present in response we aren't doing anything, do something about it to check for XSS. maybe still check for unfiltered characters and inform user in cli that Content-Type header wasn't present in response
        debug_print(f"{GRAY}[~] Content-Type header is not present in response headers so can't determine if response is HTML type or not{RESET}", newline=True)
        # if content type header is not found function returns None
        return None
    # If the response type is HTML, then tests for unfiltered special characters
    elif response_is_html is True:
        if worthy_only is True:
            if refcheck:
                special_characters = ["<", ">", "\"", "x"]
            else:
                special_characters = ["<", ">", "\""]
        else:
            if refcheck:
                special_characters = ["<", ">", "\"", "'", "/", "$", "|", "(", ")", "`", ":", ";", "{", "}", "x"]
            else:
                special_characters = ["<", ">", "\"", "'", "/", "$", "|", "(", ")", "`", ":", ";", "{", "}"]

        unfiltered_special_chars = []

        # checks unfiltered special characters by sending a request for each special character. 
        for s_character in special_characters:
            #* always keep the payload to check in lowercase, coz upon checking of payload in response body, lowercased response body is used
            char_ref_check_payload = f"aprefix{s_character}asuffix"  # unfiltered special character reflection checking payload

            # special character checking payload url encoded (firefox)
            char_ref_check_payload_encoded = str(quote(char_ref_check_payload, safe="/$|()`:;{}"))  # from special characters list these are the characters that firefox does not automatically URL encode / $ | ( ) ` : ; { }  that's why not URL encoding them.

            first_try_fail = None  # reinitialize first attempt failure check flag, since could have been set upside during content type checking
            detected_payload_reflection = detect_payload_reflection(url=modified_url, target_param=target_param, payload=char_ref_check_payload, proxy_url=proxy_url)
            # On the first request, the request might fail coz of connection error, server error, or unexpected response; causing detect_payload_reflection() to return None. Since we can't unpack None into a tuple, we first check if the function returned a tuple value by checking if it didn't return None before attempting unpacking.
            if detected_payload_reflection is not None:
                response_body, raw_response = detected_payload_reflection
            else:
                debug_print(f"{YELLOW}[!] When checking for unfiltered characters request failed{RESET}", newline=True)
                # return unfiltered_special_chars

            if  raw_response.status_code == 429:
                if nocolour:
                    print(f"[~] Response code: {raw_response.status_code}. Probably rate limited. For URL: {modified_url}")
                else:
                    print(f"\033[31m[~] Response code: {raw_response.status_code}. Probably rate limited.\033[0m \033[90mFor URL: {modified_url}\033[0m")

            # If the current special character check payload is found in the response body, add the special character to the list of unfiltered special characters. (the special character in payload is encoded automatically by requests library when making GET request)
            if char_ref_check_payload in response_body.lower():
                unfiltered_special_chars.append(s_character)
                debug_print(f"{GREEN}[+] Unfiltered special characters reflection found in response body: {s_character}{RESET}", newline=True)
                if verbose is True:
                    # Prettify HTML for structure
                    soup = BeautifulSoup(response_body, "html.parser")
                    pretty_html = soup.prettify()
                    # Highlight prettified HTML
                    highlighted_response_body = highlight(pretty_html, HtmlLexer(), TerminalFormatter())
                    print(f"{GREEN}[+] Respone body for {s_character}:{RESET}\n{highlighted_response_body}")
                    print("-" * terminal_width)
            # if --raw-payload option is used in cli
            if raw_payload:
                # If above the url encoded special character payload was not found in response body, below elif statement retries by sending the same payload without URL encoding (whole URL is url encoded, just the payload is not). The goal is to send a fully url encoded URL **except** the payload, which remains raw (unencoded) and search for that raw payload in the response body to determine if the current special character is unfiltered or not before giving up. Since the `requests` library automatically encodes all parameters, we use `curl` to preserve raw unencoded character in payload.
                if char_ref_check_payload not in response_body.lower():
                    #? maybe if these characters are included in url { } ` [ ]  curl requires them to be prepended by \ to make a successful request, so to make things easier here only check for < > " ' characters to be unfiltered? But the tool is working fine finding all the special characters using curl too. Test yourself in the URL: https://www.t-mobile.com/signin?state=sdfxx

                    # special character checking payload without being url encoded
                    # char_ref_check_payload_nonencoded = f"aprefix\\{s_character}asuffix"
                    char_ref_check_payload_nonencoded = f"aprefix{s_character}asuffix"

                    # URL with target parameter value replaced with the raw (non-URL-encoded) special character checking payload
                    modified_url = modified_url_param(url=modified_url, target_param=target_param, replace_value=char_ref_check_payload_nonencoded)

                    if modified_url is not None:
                        debug_print(f"{GRAY}modified_url{RESET}", newline=True)
                        # url = "https://www.t-mobile.com/signin?state=sdfxx\\{sdfxx"  # example url when storing url in variable to pass in curl using subprocess (in linux curl you only have to escape invalid URL characters once using \ but in python code to escape it you have to use it two times \\)

                        # URL-encode the entire URL string except URL reserved characters. This ensures the URL is properly encoded except for syntax-critical characters (allowing proper encoding of special characters without breaking the structural components of the URL). If any part of the URL is already encoded, `quote()` won't double-encode it.
                        encoded_url = str(quote(modified_url, safe="#!$%&'()*+,/:;=?@[]"))  # characters passed in `safe` parameter are URL reserved characters (those characters won't be url encoded)
                        debug_print(encoded_url, newline=True)

                        # URL-encode the non-encoded special character payload so we can later replace the encoded version in the URL with its raw (non-URL-encoded) form. This lets us send a GET request where the special character in the payload is preserved as-is, without being URL-encoded.  char_ref_check_payload_encoded = str(quote(char_ref_check_payload_nonencoded, safe="\\"))
                        char_ref_check_payload_encoded = str(quote(char_ref_check_payload_nonencoded))

                        # In the URL, replace the URL-encoded payload with the non-encoded payload, so the final URL is fully encoded except for the special character payload.
                        url = encoded_url.replace(char_ref_check_payload_encoded, char_ref_check_payload_nonencoded)

                        # curl url should not include any spaces ' ' without being url encoded first.
                        # in linux i was able to send these characters between aprefix asuffix without url encoding using curl cmd utility: < > % { } \ | ` [ ] ^   . however, had to escape { } ` [ ] characters by prepending them with \
                        # curl -k -x "http://127.0.0.1:9090" --compressed --output - "https://www.t-mobile.com/signin?state=sdfxx\{sdfxx"
                        # without '--compressed' flag, curl was providing binary response instead of real HTML response. so it's an important flag.

                        ## Finally making GET requests using curl where special character payload in the URL is sent raw (not URL-encoded),while the rest of the URL is URL-encoded.

                        # if in cli --proxy flag is not used, make curl request without proxy
                        if proxy_url is None:
                            cmd = [
                                "curl",
                                "-k",
                                "--compressed",
                            ]

                            for k, v in headers.items():
                                cmd.extend(["-H", f"{k}: {v}"])

                            cmd.append(url)
                        # if in cli --proxy flag is used, make curl request with proxy
                        else:
                            cmd = [
                                "curl",
                                "-k",
                                "-x", proxy_url,
                                "--compressed",
                            ]

                            for k, v in headers.items():
                                cmd.extend(["-H", f"{k}: {v}"])

                            cmd.append(url)
                        
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        response_body = (result.stdout)

                        # If the current special character check payload is found in the response body, add the special character to the list of unfiltered special characters.
                        if char_ref_check_payload_nonencoded in response_body.lower():
                            unfiltered_special_chars.append(s_character)
                            debug_print(f"{GREEN}[+] Unfiltered special characters reflection found in response body: {s_character}{RESET}", newline=True)
                            if verbose is True:
                                # Prettify HTML for structure
                                soup = BeautifulSoup(response_body, "html.parser")
                                pretty_html = soup.prettify()
                                # Highlight prettified HTML
                                highlighted_response_body = highlight(pretty_html, HtmlLexer(), TerminalFormatter())
                                print(f"{GREEN}[+] Respone body for {s_character}:{RESET}\n{highlighted_response_body}")
                                print("-" * terminal_width)
                    else:
                        # if modified_url returns None
                        debug_print(f"modified_url is {modified_url}", newline=True)


        return unfiltered_special_chars


def check_each_param_for_unfiltered_char(url):
    """Inspects each parameter in the given URL (both query and path-embedded) to detect unfiltered special characters through reflection testing.

    Args:
        url (str): The URL to test, which may contain query and/or path-embedded parameters.

    Returns:
        list: A list containing tuples for each parameter in URL being tested containing URL (string), Parameter Tested (string), Unfiltered Special Characters detected (list).
    """
    
    def detect_paramters(url):
        """Wrapper function which returns a list of all parameter names in a URL, including those without assigned values (e.g., "page" in "?page" or "?page=")

        Definitions:
            excluding empty keys: it means ignoring parameters that have no name before the equals sign, such as in =value. (e.g. http://example.com/home?=value&page=2)

        Args:
            url (str): URL whose path-embedded and query parameter names to be extracted.

        Returns:
            list: All parameter names from the URL (path-embedded and query), excluding empty keys.
        """

        # For each url parameter query or path-embedded find unfiltered characters using unfiltered_characters function.
        # url = "https://example.com/products;category=electronics;brand=;items;id=1;color=black?sort=price&order=&page"  # example testing URL
        parsed = urlparse(url)

        # Extract path-embedded parameter names
        path_param_names = [pair.split("=")[0] for pair in parsed.params.split(";") if pair]

        # Extract query parameter names (even if no value is assigned)
        query_param_names = [pair.split("=")[0] for pair in parsed.query.split("&") if pair]

        debug_print(f"{GRAY}Path-embedded parameter names: {RESET}", path_param_names)
        debug_print(f"{GRAY}Query parameter names: {RESET}", query_param_names)

        all_parameters = path_param_names + query_param_names

        # Removes empty string elements from all_parameters if any present, caused by parameters with no name before the equal sign such as "=value" in http://example.com/home?=value&page=2
        # filtered_parameters_list = [item for item in all_parameters if item != ""]
        filtered_parameters_list = []
        for item in all_parameters:
            # If the parameter name is not an empty string, add it to the filtered list
            if item != "":
                filtered_parameters_list.append(item)
            # If the parameter name is empty (e.g., "=value"), log a debug message
            else:
                debug_print(f"{GRAY}[~] URL has parameter value but not name{RESET}", newline=True)

        return filtered_parameters_list


    parameters_to_check = detect_paramters(url=url)
    debug_print(f"parameters_to_check {parameters_to_check}")

    result = []

    # for each embedded or query parameters in URL, find unfiltered special characters
    for parameter in parameters_to_check:
        # if current parameter being check does not have a value, add value to it. doing this to avoid any potential issues in modification url down the road.
        url = replace_empty_url_param(url=url, target_param=parameter, default_value="123")
        #TODO: is proxy_url properly passed everywhere from here?

        unfiltered_characters_detected = unfiltered_characters_func(modified_url=url, target_param=parameter, proxy_url=proxy_url)

        url = url
        parameter = parameter
        unfiltered_characters = unfiltered_characters_detected

        result.append((url, parameter, unfiltered_characters))  # appends tuple

    debug_print(result)

    return result  # using index zero so it doesn't return the unnecessary outward list


# ensures the script runs only when executed (not imported).
if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="A script to find unfiltered special characters in URLs which could lead to reflected XSS.")
    # Define expected arguments
    parser.add_argument(
        "--proxy",
        type=str,
        default=None,
        help="URL of the proxy the requests should go through (default: None). Example: --proxy http://127.0.0.1:9090"
    )
    # parser.add_argument(
    #     "--consistency",
    #     type=int,
    #     default=3,
    #     help="Minimum number of consistent results required out of 5 (default: 3). Sets consistent to True if the total number of reflections is the same in at least provided number out of all (total 5 in for loop) requests"
    # )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output [output will contain response body too] (default: False)"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable print debugging messages (default: False)"
    )
    parser.add_argument(
        "--worthy",
        action="store_true",
        help="""Only search for < > " ' special characters to be unfiltered. (default: False)"""
    )
    parser.add_argument(
        "--raw-payload",
        action="store_true",
        help="""Check for reflection of raw special characters to be unfiltered too, i.e. without URL encoding characters like < > " in payloads. (default: False)"""
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Number of URLs to process in each batch. In other words, number of URL to check for unfiltered characters simultaneously."
    )
    parser.add_argument(
        "--nocolour",
        action="store_true",
        help="Disable colour output (default: False)"
    )
    parser.add_argument(
        "--refcheck",
        action="store_true",
        help="Add 'x' letter to special characters list (default: False)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file to save results to."
    )
    parser.add_argument(
        "--output-worthy",
        type=str,
        default=None,
        help="Output file to save only worthy special characters if found."
    )

    argcomplete.autocomplete(parser)
    # Parse the arguments
    args = parser.parse_args()

    # Access the arguments
    proxy_url = args.proxy
    # consistency = args.consistency
    verbose = args.verbose
    debug_mode = args.debug  # Global variable for debug_mode, which determines by default whether debugging messages should be printed or not.
    worthy_only = args.worthy
    raw_payload= args.raw_payload
    threads = args.threads
    nocolour = args.nocolour
    refcheck = args.refcheck
    output = args.output
    output_worthy = args.output_worthy

    # If --nocolour flag is passed via command line, then colour colour variabes won't make effect in code even if they are used
    if nocolour is True:
        YELLOW = ""
        GRAY = ""
        GREEN = ""
        CYAN = ""
        PINK = ""
        RESET = ""
    else:
        # ANSI escape codes to color specific parts of printed output for visibility and categorization.
        YELLOW = "\033[93m"
        GRAY = "\033[90m"
        GREEN = "\033[32m"
        CYAN = "\033[96m"
        PINK = "\033[95m"
        RESET = "\033[0m"

    # print("Proxy URL:", proxy_url)
    # print("Consistency:", consistency)

    cwd = os.path.abspath(os.getcwd())
    if output:
        output_file = os.path.expanduser(f"{output}")
    if output_worthy:
        output_worthy_file = os.path.expanduser(f"{output_worthy}")

    # These request headers will be used throughout the tool; define here once and forget the worry about defining headers again.
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
        "Accept": "*/*",
        "Accept-Language": "en;q=0.5, *;q=0.1",
        "Accept-Encoding": "gzip, deflate, br"
    }

    # if use of threading isn't specified in the command line argument using --threads
    if threads is None:
        for url in sys.stdin:
            url = url.strip()
            if url:
                # add '123' value to any empty url parameters
                # url = replace_empty_url_params(url)

                try:
                    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
                    check_alive = requests.get(url, timeout=10, proxies=proxies, verify=False, allow_redirects=False, headers=headers)
                # Handles all request failures
                except Exception as e:
                    # moves to the next url if couldn't get a response for current URL
                    continue

                # unfiltered characters for each parameter in URL (also contains url and paramter name)
                parameter_results = check_each_param_for_unfiltered_char(url=url)

                for result in parameter_results:
                    # if unfiltered characters is not None or not empty then only print the unfiltered characters result
                    if result[2] is None:
                        pass
                    elif len(result[2]) == 0:
                        pass
                    else:
                        # If worthy_only is True and neither '<' nor '>' is present in the unfiltered characters, then doesn't output " or ' characters even if they are unfiltered. (comments lie, code doesn't!)
                        if worthy_only is True:
                            if "<" in result[2] or ">" in result[2] or '"' in result[2] or "'" in result[2] or "x" in result[2]:
                                print("")
                                # print(f"{CYAN}URL:{RESET} {result[0]} {CYAN}Param:{RESET} {result[1]} {PINK}Unfiltered:{RESET} {result[2]}")
                                print(f"{CYAN}URL:{RESET} {result[0]} {CYAN}Param:{RESET} {result[1]} {PINK}Unfiltered:{RESET} [ {' '.join(result[2])} ]")
                                if output:
                                    with open(output_file, "a") as f:
                                        f.write(f"URL: {result[0]} Param: {result[1]} Unfiltered: [ {' '.join(result[2])} ]\n")
                                if output_worthy:
                                    if "<" in result[2] or ">" in result[2] or '"' in result[2] or "'" in result[2]:
                                        with open(output_worthy_file, "a") as f:
                                            f.write(f"URL: {result[0]} Param: {result[1]} Unfiltered: [ {' '.join(result[2])} ]\n")
                        # if worthy_only is False then print every character that is found to be unfiltered
                        else:
                            print("")
                            print(f"{CYAN}URL:{RESET} {result[0]} {CYAN}Param:{RESET} {result[1]} {PINK}Unfiltered:{RESET} [ {' '.join(result[2])} ]")
                            if output:
                                with open(output_file, "a") as f:
                                    f.write(f"URL: {result[0]} Param: {result[1]} Unfiltered: [ {' '.join(result[2])} ]\n")
                            if output_worthy:
                                if "<" in result[2] or ">" in result[2] or '"' in result[2] or "'" in result[2]:
                                    with open(output_worthy_file, "a") as f:
                                        f.write(f"URL: {result[0]} Param: {result[1]} Unfiltered: [ {' '.join(result[2])} ]\n")

    # if use of threading is specified in the command line argument using --threads
    if type(threads) is int:
        def check(url):
            if url:

                try:
                    proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
                    check_alive = requests.get(url, timeout=10, proxies=proxies, verify=False, allow_redirects=False, headers=headers)
                # Handles all request failures
                except Exception as e:
                    # moves to the next url if couldn't get a response for current URL
                    check_alive = False

                # if provided url provides a response i.e. it is not dead
                if check_alive is not False:
                    # unfiltered characters for each parameter in URL (also contains url and paramter name)
                    parameter_results = check_each_param_for_unfiltered_char(url=url)

                    for result in parameter_results:
                        # if unfiltered characters is not None or not empty then only print the unfiltered characters result
                        if result[2] is None:
                            pass
                        elif len(result[2]) == 0:
                            pass
                        else:
                            # print("")
                            # # print(f"{CYAN}URL:{RESET} {result[0]} {CYAN}Param:{RESET} {result[1]} {PINK}Unfiltered:{RESET} {result[2]}")
                            # print(f"{CYAN}URL:{RESET} {result[0]} {CYAN}Param:{RESET} {result[1]} {PINK}Unfiltered:{RESET} [ {' '.join(result[2])} ]")

                            # If worthy_only is True and neither '<' nor '>' is present in the unfiltered characters, then doesn't output " or ' characters even if they are unfiltered.
                            if worthy_only is True:
                                if "<" in result[2] or ">" in result[2] or '"' in result[2] or "'" in result[2] or "x" in result[2]:
                                    print("")
                                    # print(f"{CYAN}URL:{RESET} {result[0]} {CYAN}Param:{RESET} {result[1]} {PINK}Unfiltered:{RESET} {result[2]}")
                                    print(f"{CYAN}URL:{RESET} {result[0]} {CYAN}Param:{RESET} {result[1]} {PINK}Unfiltered:{RESET} [ {' '.join(result[2])} ]")
                                    if output:
                                        with open(output_file, "a") as f:
                                            f.write(f"URL: {result[0]} Param: {result[1]} Unfiltered: [ {' '.join(result[2])} ]\n")
                                    if output_worthy:
                                        if "<" in result[2] or ">" in result[2] or '"' in result[2] or "'" in result[2]:
                                            with open(output_worthy_file, "a") as f:
                                                f.write(f"URL: {result[0]} Param: {result[1]} Unfiltered: [ {' '.join(result[2])} ]\n")
                            # if worthy_only is False then print every character that is found to be unfiltered
                            else:
                                print("")
                                print(f"{CYAN}URL:{RESET} {result[0]} {CYAN}Param:{RESET} {result[1]} {PINK}Unfiltered:{RESET} [ {' '.join(result[2])} ]")
                                if output:
                                    with open(output_file, "a") as f:
                                        f.write(f"URL: {result[0]} Param: {result[1]} Unfiltered: [ {' '.join(result[2])} ]\n")
                                if output_worthy:
                                    if "<" in result[2] or ">" in result[2] or '"' in result[2] or "'" in result[2]:
                                        with open(output_worthy_file, "a") as f:
                                            f.write(f"URL: {result[0]} Param: {result[1]} Unfiltered: [ {' '.join(result[2])} ]\n")


        # threads = 3  # Number of URLs to process in each batch
        urls = []  # Temporary list to store each batch of URLs

        # Read lines from stdin
        for url in sys.stdin:
            url = url.strip()
            if url:
                urls.append(url)
                # If we have a complete batch, process and reset
                if len(urls) == threads:
                    debug_print(urls)  # list containing `threads` number of urls
                    # for url in urls:
                    #     print(url)
                    debug_print(f"{threads} number of batch over\n")  # Indicate end of this batch

                    # t1 = threading.Thread(target=check, args=(urls[0],))
                    # t2 = threading.Thread(target=check, args=(urls[1],))
                    # t3 = threading.Thread(target=check, args=(urls[2],))

                    # t1.start()
                    # t2.start()
                    # t3.start()

                    threads_list = []

                    for i in range(threads):
                        t = threading.Thread(target=check, args=(urls[i],))
                        threads_list.append(t)
                        t.start()

                    # Wait for all threads in this batch to finish (this makes the number passed to control threads via --threads properly function)
                    for t in threads_list:
                        t.join()

                    urls.clear()  # Clear list for the next batch

        # Process any remaining URLs that didn't form a full batch
        if urls:
            for url in urls:
                debug_print(f"Non full batch url {url}")
                check(url=url)
            debug_print("3 batch over")  # Still mark the end even for partial batch



    ## When breakpoint debugging
    # url = "https://in.search.yahoo.com/search?p=sdf333&fr=sfp&fr2=p%3As%2Cv%3Asfp%2Cm%3Asb-top&iscqry=&guccounter=1"
    # url = "https://in.search.yahoo.com/search?p=sdf333&fr=sfp"
    # result = check_each_param_for_unfiltered_char(url=url)
    # print("")
    # print(f"URL: {result[0]}")
    # print(f"Parameter: {result[1]}")
    # print(f"Unfiltered Characters: {result[2]}")
    # print(result)
