# Necessary Python libraries
import colorama
from colorama import Fore, Style, Back
colorama.init(autoreset=True)
import re, os, sys
from bs4 import BeautifulSoup
import pprint
from urllib.parse import urlparse
import email
from IPy import IP
import email.header
import csv
from collections import Counter
import pandas as pd
import joblib

# Set the encoding to UTF-8 (no need for this in Python 3 as UTF-8 is the default)

'''
Additional pre-processing functions
'''

print(Fore.MAGENTA + Back.YELLOW + 30*"*" + " PHISHECTOR " + 30*"*" + Style.RESET_ALL)
test_path = input(Fore.BLUE + "Enter path of folder where mail is present: ")

# Difference between two lists
def difference(first, second):
    second = set(second)
    return [item for item in first if item not in second]

# Counts the number of characters in a given string
def count_characters(string):
    return len(string) - string.count(' ') - string.count('\n')

# Extract URLs in the message
def extract_urls(msg):
    mail = str(msg)
    urls = re.findall(r"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+", mail)
    return urls

# Extract anchor URLs in the message
def extract_anchor_urls(msg):
    anchor_urls = []
    soup = BeautifulSoup(msg, 'html.parser')
    for link in soup.findAll('a', attrs={'href': re.compile("^http[s]?://")}):
        anchor_urls.append(link.get('href'))
    return anchor_urls

# Extract the domain from the email
def get_email_domain(string):
    domain = re.search(r"@[\w.]+", string)
    return domain.group()[1:] if domain else None

# Extract domain from URL
def get_url_domain(url):
    domain = None
    if url:
        if u'@' in str(url):
            domain = get_email_domain(str(url))
        else:
            parsed_uri = urlparse(url)
            domain = '{uri.netloc}'.format(uri=parsed_uri)
            if domain.startswith("www."):
                return domain[4:]
    return domain

# Find the most frequent URL in a list of URLs
def most_common_url(urls):
    return max(set(urls), key = urls.count) if urls else None

# Remove file if it exists
def remove_if_exists(filename):
    try:
        os.remove(filename)
    except OSError:
        pass

'''
Functions needed to extract the necessary fields
'''

# Read the files (filenames) in the chosen path
def get_files(path):
    return os.listdir(path)

# Extract the message from the email (read as string)
def extract_msg(path, mail_file):
    mail_file = os.path.join(path, mail_file)
    with open(mail_file, "r", encoding="latin1") as fp:
        mail = fp.read()
    msg = email.message_from_string(mail)
    return msg

# Extract the body from the message
def extract_body(msg):
    body_content = ""
    if msg.is_multipart():
        for payload in msg.get_payload():
            body_content += str(payload.get_payload())
    else:
        body_content += msg.get_payload()
    return body_content

# Extract the subject from the message
def extract_subj(msg):
    subject = msg.get('Subject', 'None')
    if subject is None:
        return "None"
    decode_subj = email.header.decode_header(subject)[0]
    try:
        subj_content = str(decode_subj[0])
    except:
        subj_content = "None"
    return subj_content

# Extract sender address from message
def extract_send_address(msg):
    from_field = msg.get('From', 'None')
    if from_field is None:
        return "None"
    decode_send = email.header.decode_header(from_field)[0]
    try:
        send_address = str(decode_send[0])
    except:
        send_address = "None"
    return send_address

# Extract reply-to address from message
def extract_replyTo_address(msg):
    reply_to_field = msg.get('Reply-To', 'None')
    if reply_to_field is None:
        return "None"
    decode_replyTo = email.header.decode_header(reply_to_field)[0]
    try:
        replyTo_address = str(decode_replyTo[0])
    except:
        replyTo_address = "None"
    return replyTo_address

# Extract the modal URL from message
def extract_modal_url(msg):
    urls = extract_urls(msg)
    modal_url = most_common_url(urls)
    return modal_url

# Extract all links
def extract_all_links(msg):
    links = []
    soup = BeautifulSoup(msg, 'html.parser')
    for link in soup.findAll('a'):
        href = link.get('href')
        if href:
            links.append(href)
    
    all_urls = extract_urls(msg)
    anchor_urls = extract_anchor_urls(msg)
    
    urls = difference(all_urls, anchor_urls)
    links.extend(urls)
    return links or []

'''
Extract the necessary fields
'''

# Run the function to extract necessary fields of a mail
def extract_necessary_fields(path, mail):
    necessary_fields = {}
    msg = extract_msg(path, mail)
    
    necessary_fields['body'] = extract_body(msg)
    necessary_fields['subj'] = extract_subj(msg)
    necessary_fields['send'] = extract_send_address(msg)
    necessary_fields['replyTo'] = extract_replyTo_address(msg)
    necessary_fields['modalURL'] = extract_modal_url(msg)
    necessary_fields['links'] = extract_all_links(str(msg)) or []  # Ensure it's a list, not None
    
    return necessary_fields

'''
Functions to extract body-based attributes
'''

# Boolean: if HTML is present or not
def body_html(body_content):
    return bool(BeautifulSoup(body_content, "html.parser").find())

# Boolean: if HTML has <form> or not
def body_forms(body_content):
    return bool(BeautifulSoup(body_content, "html.parser").find("form"))

# Integer: number of words in the body
def body_noWords(body_content):
    return len(body_content.split())

# Integer: number of characters in the body
def body_noCharacters(body_content):
    return count_characters(body_content)

# Integer: number of distinct words in the body
def body_noDistinctWords(body_content):
    return len(Counter(body_content.split()))

# Float: richness of the text (body)
def body_richness(body_noWords, body_noCharacters):
    try:
        return float(body_noWords) / body_noCharacters
    except:
        return 0

# Integer: number of function words in the body
def body_noFunctionWords(body_content):
    body_noFunctionWords = 0
    wordlist = re.sub("[^A-Za-z]", " ", body_content.strip()).lower().split()
    function_words = ["account", "access", "bank", "credit", "click", "identity", "inconvenience", "information", 
                      "limited", "log", "minutes", "password", "recently", "risk", "social", "security", "service", "suspended"]
    for word in function_words:
        body_noFunctionWords += wordlist.count(word)
    return body_noFunctionWords

# Boolean: if body has the word 'suspension' or not
def body_suspension(body_content):
    return "suspension" in body_content.lower()

# Boolean: if body has the phrase 'verify your account' or not
def body_verifyYourAccount(body_content):
    phrase = "verifyyouraccount"
    content = re.sub(r"[^A-Za-z]", "", body_content.strip()).lower()
    return phrase in content
  
def extract_body_attributes(body_content):
    body_attributes = {}
    
    body_attributes['body_html'] = body_html(body_content)
    body_attributes['body_forms'] = body_forms(body_content)
    body_attributes['body_noWords'] = body_noWords(body_content)
    body_attributes['body_noCharacters'] = body_noCharacters(body_content)
    body_attributes['body_noDistinctWords'] = body_noDistinctWords(body_content)
    body_attributes['body_richness'] = body_richness(body_attributes['body_noWords'], body_attributes['body_noCharacters'])
    body_attributes['body_noFunctionWords'] = body_noFunctionWords(body_content)
    body_attributes['body_suspension'] = body_suspension(body_content)
    body_attributes['body_verifyYourAccount'] = body_verifyYourAccount(body_content)
    
    return body_attributes

'''
Functions to extract subject line based attributes
'''

# Boolean: Check if the email is a reply to any previous mail
def subj_reply(subj_content):
    return subj_content.lower().startswith("re:")

# Boolean: Check if the email is a forward from another mail
def subj_forward(subj_content):
    return subj_content.lower().startswith("fwd:")

# Integer: number of words in the subject
def subj_noWords(subj_content):
    return len(subj_content.split())

# Integer: number of characters in the subject
def subj_noCharacters(subj_content):
    return count_characters(subj_content)

# Float: richness of the text (subject)
def subj_richness(subj_noWords, subj_noCharacters):
    try:
        return float(subj_noWords) / subj_noCharacters
    except:
        return 0

# Boolean: if subject has the word 'verify' or not
def subj_verify(subj_content):
    return "verify" in subj_content.lower()

def extract_subj_attributes(subj_content):
    subj_attributes = {}
    
    subj_attributes['subj_reply'] = subj_reply(subj_content)
    subj_attributes['subj_forward'] = subj_forward(subj_content)
    subj_attributes['subj_noWords'] = subj_noWords(subj_content)
    subj_attributes['subj_noCharacters'] = subj_noCharacters(subj_content)
    subj_attributes['subj_richness'] = subj_richness(subj_attributes['subj_noWords'], subj_attributes['subj_noCharacters'])
    subj_attributes['subj_verify'] = subj_verify(subj_content)
    
    return subj_attributes

'''
Functions to extract sender-based attributes
'''

# Boolean: sender is an IP address
def send_isIPAddress(send_address):
    domain = get_email_domain(send_address)
    try:
        IP(domain)
        return True
    except:
        return False

# Boolean: sender address is suspicious (if special characters are present)
def send_isSuspicious(send_address):
    domain = get_email_domain(send_address)
    if domain:
        if re.search("[^a-zA-Z0-9.]", domain) is None:
            return False
        else:
            return True
    return False

# Integer: number of characters in the domain name
def send_domainLength(send_address):
    domain = get_email_domain(send_address)
    return len(domain) if domain else 0

# Boolean: reply-to is different from sender address
def send_replyToDifferent(send_address, replyTo_address):
    return send_address != replyTo_address

# Boolean: reply-to is suspicious
def send_replyToSuspicious(replyTo_address):
    domain = get_email_domain(replyTo_address)
    if domain:
        if re.search("[^a-zA-Z0-9.]", domain) is None:
            return False
        else:
            return True
    return False

def extract_send_attributes(send_address, replyTo_address):
    send_attributes = {}
    
    send_attributes['send_isIPAddress'] = send_isIPAddress(send_address)
    send_attributes['send_isSuspicious'] = send_isSuspicious(send_address)
    send_attributes['send_domainLength'] = send_domainLength(send_address)
    send_attributes['send_replyToDifferent'] = send_replyToDifferent(send_address, replyTo_address)
    send_attributes['send_replyToSuspicious'] = send_replyToSuspicious(replyTo_address)
    
    return send_attributes

'''
Functions to extract URL-based attributes
'''

# Boolean: URL is an IP address
def url_isIPAddress(modal_url):
    try:
        IP(modal_url)
        return True
    except:
        return False

# Integer: number of dots in domain name of URL
def url_noDots(modal_url):
    domain = get_url_domain(modal_url)
    return domain.count('.') if domain else 0

# Integer: number of slashes in URL
def url_noSlashes(modal_url):
    return modal_url.count('/') if modal_url else 0

# Integer: number of characters in domain name
def url_domainLength(modal_url):
    domain = get_url_domain(modal_url)
    return len(domain) if domain else 0

# Integer: number of digits in URL
def url_noDigits(modal_url):
    return sum(c.isdigit() for c in modal_url) if modal_url else 0

# Integer: number of query parameters in URL
def url_noParameters(modal_url):
    parsed_uri = urlparse(modal_url)
    return len(parsed_uri.query) if parsed_uri.query else 0

# Integer: number of characters in the longest link
def links_maxLength(links):
    if isinstance(links, list) and links:
        return max(len(link) for link in links)
    return 0

# Boolean: links use encryption (HTTPS)
def links_useEncryption(links):
    for link in links:
        if link.startswith("https://"):
            return True
    return False

def extract_url_attributes(modal_url, links):
    url_attributes = {}
    
    url_attributes['url_isIPAddress'] = url_isIPAddress(modal_url)
    url_attributes['url_noDots'] = url_noDots(modal_url)
    url_attributes['url_noSlashes'] = url_noSlashes(modal_url)
    url_attributes['url_domainLength'] = url_domainLength(modal_url)
    url_attributes['url_noDigits'] = url_noDigits(modal_url)
    url_attributes['url_noParameters'] = url_noParameters(modal_url)
    url_attributes['links_maxLength'] = links_maxLength(links)
    url_attributes['links_useEncryption'] = links_useEncryption(links)
    
    return url_attributes

'''
Classify email based on attributes
'''

def classify_email(attributes):
    # Example criteria for phishing
    if attributes['subj_verify'] or attributes['body_suspension'] or \
       attributes['url_isIPAddress'] or attributes['send_isIPAddress'] or \
       attributes['send_isSuspicious'] or attributes['body_noFunctionWords'] > 3:
        return 'Phishing'
    else:
        return 'Legitimate'

'''
Run the extraction
'''

def main():
    files = get_files(test_path)
    extracted_data = []
    
    for mail in files:
        necessary_fields = extract_necessary_fields(test_path, mail)
        
        body_attributes = extract_body_attributes(necessary_fields['body'])
        subj_attributes = extract_subj_attributes(necessary_fields['subj'])
        send_attributes = extract_send_attributes(necessary_fields['send'], necessary_fields['replyTo'])
        url_attributes = extract_url_attributes(necessary_fields['modalURL'], necessary_fields['links'])
        
        combined_attributes = {**body_attributes, **subj_attributes, **send_attributes, **url_attributes}
        
        # Add classification
        combined_attributes['classification'] = classify_email(combined_attributes)
        
        extracted_data.append(combined_attributes)
    
    df = pd.DataFrame(extracted_data)
    df.to_csv('extracted_data.csv', index=False)
    print(Fore.GREEN + "Extraction complete. Data saved to extracted_data.csv")

if __name__ == "__main__":
    main()
