import sys  # Used to read from standard input (piped data).
import re
import requests  # For making HTTP GET requests.
from urllib.parse import (
    urlparse,
    parse_qs,
    urlencode,
    urlunparse,
)  # For safely parsing and reconstructing URLs and query strings.
import urllib3  # For handling SSL warning suppression

# Disable SSL certificate warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============ Global Variables ============
# Global variable for debug_mode, which determines by default whether debugging messages should be printed or not.
debug_mode = True  # TODO: turn default debug mode off, let the user spcifiy want debug msges or not via cmd line.

# ANSI escape codes to color specific parts of printed output for visibility and categorization.
YELLOW = "\033[93m"
GRAY = "\033[90m"
GREEN = "\033[32m"
CYAN = "\033[96m"
PINK = "\033[95m"
RESET = "\033[0m"


#! debug_print does NOT print regex results
# passing f-strings to debug_print function - this function can handle f-strings directly (e.g., debug_print(f"one plus one = {1+1}")) and f-strings in variables passed as f-strings (e.g., 1plus1 = f"one plus one = {1+1}"; debug_print(f"{1plus1}")), but not f-string variables directly (e.g., 1plus1 = f"one plus one = {1+1}"; debug_print(1plus1)).
def debug_print(message, newline=True):
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


import os  # Provides functions for interacting with the operating system, such as path manipulation

# import pytest  # Even though pytest is installed via pip, we still need to import it explicitly to use its features like @pytest.mark.parametrize in this script
import sys

# Adds the parent directory of the current file to the system path.
# This is necessary so Python can find and import 'pxss.py' from the parent directory.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
# Imports the 'modified_url_param' function from 'pxss.py' located in the parent directory
from pxss import modified_url_param


def test_query_modified_url_param():

    # test data with query parameters
    test_data = [
        (
            "https://example.com/page?user=alice&id=123",
            "id",
            "999",
            "https://example.com/page?user=alice&id=999",
        ),
        (
            "https://example.com/page?foo=bar&price=100&price=200",
            "price",
            "aprefixpriceapsuffix",
            "https://example.com/page?foo=bar&price=aprefixpriceapsuffix",
        ),
    ]

    for data in test_data:
        url = data[0]
        target_param = data[1]
        replace_value = data[2]
        expected = data[3]

        debug_print(
            f"Provided URL: {url}\nTarget paramter: {target_param}\nReplace value: {replace_value}"
        )
        result = modified_url_param(url, target_param, replace_value)
        # debug_print(f"Modified URL: {result}")
        print(result)
        assert result == expected


def test_path_embedded_modified_url_param():

    # test data with path-embedded parameters
    test_data = [
        (
            "https://example.com/resource;token=abc123;mode=edit?x=1",
            "token",
            "newtoken",
            "https://example.com/resource;token=newtoken&mode=edit?x=1",
        ),
        (
            "https://example.com/resource;mode=edit;role=admin",
            "role",
            "guest",
            "https://example.com/resource;mode=edit&role=guest",
        ),
        (
            "https://example.com/resource;mode=edit;role=admin?foo1=bor&foo2=yeah",
            "foo1",
            "bro",
            "https://example.com/resource;mode=edit;role=admin?foo1=bro&foo2=yeah",
        ),
    ]

    for data in test_data:
        url = data[0]
        target_param = data[1]
        replace_value = data[2]
        expected = data[3]

        debug_print(
            f"Provided URL: {url}\nTarget paramter: {target_param}\nReplace value: {replace_value}"
        )
        result = modified_url_param(url, target_param, replace_value)
        # debug_print(f"Modified URL: {result}")
        print(result)
        assert result == expected


def test_not_present_modified_url_param():

    # test data with parameter not present in the URL (should return None)
    test_data = [
        ("https://example.com/page?name=alex", "missing_param", "value", None),
        ("https://example.com/path;abc=123", "not_in_path", "zzz", None),
    ]

    for data in test_data:
        url = data[0]
        target_param = data[1]
        replace_value = data[2]
        expected = data[3]

        debug_print(
            f"Provided URL: {url}\nTarget paramter: {target_param}\nReplace value: {replace_value}"
        )
        result = modified_url_param(url, target_param, replace_value)
        # debug_print(f"Modified URL: {result}")
        print(result)
        assert result == expected
