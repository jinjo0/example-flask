
# A very simple Flask Hello World app for you to get started with...

from flask import Flask,request, jsonify
import requests
import subprocess
from flask_cors import CORS, cross_origin
import sys
import re

def url_decode(encoded_str):
    import re

    # Dictionary of percent-encoded values and their corresponding characters
    hex_to_char = {
        '%20': ' ', '%21': '!', '%22': '"', '%23': '#', '%24': '$', '%25': '%',
        '%26': '&', '%27': "'", '%28': '(', '%29': ')', '%2A': '*', '%2B': '+',
        '%2C': ',', '%2D': '-', '%2E': '.', '%2F': '/', '%30': '0', '%31': '1',
        '%32': '2', '%33': '3', '%34': '4', '%35': '5', '%36': '6', '%37': '7',
        '%38': '8', '%39': '9', '%3A': ':', '%3B': ';', '%3C': '<', '%3D': '=',
        '%3E': '>', '%3F': '?', '%40': '@', '%41': 'A', '%42': 'B', '%43': 'C',
        '%44': 'D', '%45': 'E', '%46': 'F', '%47': 'G', '%48': 'H', '%49': 'I',
        '%4A': 'J', '%4B': 'K', '%4C': 'L', '%4D': 'M', '%4E': 'N', '%4F': 'O',
        '%50': 'P', '%51': 'Q', '%52': 'R', '%53': 'S', '%54': 'T', '%55': 'U',
        '%56': 'V', '%57': 'W', '%58': 'X', '%59': 'Y', '%5A': 'Z', '%5B': '[',
        '%5C': '\\', '%5D': ']', '%5E': '^', '%5F': '_', '%60': '`', '%61': 'a',
        '%62': 'b', '%63': 'c', '%64': 'd', '%65': 'e', '%66': 'f', '%67': 'g',
        '%68': 'h', '%69': 'i', '%6A': 'j', '%6B': 'k', '%6C': 'l', '%6D': 'm',
        '%6E': 'n', '%6F': 'o', '%70': 'p', '%71': 'q', '%72': 'r', '%73': 's',
        '%74': 't', '%75': 'u', '%76': 'v', '%77': 'w', '%78': 'x', '%79': 'y',
        '%7A': 'z', '%7B': '{', '%7C': '|', '%7D': '}', '%7E': '~'
    }

    # Use regex to find all percent-encoded characters
    def replace_match(match):
        code = match.group(0)
        return hex_to_char.get(code, code)

    # Replace percent-encoded characters in the input string
    decoded_str = re.sub(r'%[0-9A-Fa-f]{2}', replace_match, encoded_str)
    return decoded_str

def login(email, password):
    try:
        burp0_url = "https://my.exness.com:443/v4/wta-api/signin?captchaVersion=3"
        burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0", "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Content-Type": "application/json", "Origin": "https://my.exness.com", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Priority": "u=4", "Te": "trailers"}
        burp0_json={"action": "LOGIN", "login": "amer_zeitoun@yahoo.com", "password": "Amer1980"}
        r=requests.post(burp0_url, headers=burp0_headers, json=burp0_json, timeout=60)
        r.raise_for_status()
        data = r.json()
        return data
    except requests.exceptions.Timeout:
        data = {"error": "The request timed out. Please try again later."}
    except requests.exceptions.RequestException as e:
        data = {"error": str(e)}
    return data

def getInfo(token,refresh):
    burp0_url = "https://my.exness.com:443/v4/kyc_back/api/v1/profiles/me"
    burp0_cookies = {" JWT": token, "jwt_refresh": refresh}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0", "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Referer": "https://my.exness.com/pa/settings/security", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Te": "trailers"}
    r=requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
    data = r.json()
    first_name = data['first_name']
    phone = data['security_objects'][1]['value']

    return {"first_name":first_name, "phone":phone}

def getBalance(token,refresh,email,password):
    try:
        info  = getInfo(token,refresh)
        burp0_url = "https://my.exness.com:443/v4/wta-api/async/personal_area/account?show_partner=True&show_crypto=True&show_investor=True"
        burp0_headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0", "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate, br", "Trace-Id": "13ce50e6-3446-4345-bcc7-7fe31b11f2fe", "Sentry-Trace": "f594d2c8c20540ca80a014b558586953-a4913e1a25783e52-0", "Baggage": "sentry-environment=production,sentry-release=f75652b0e28ac8e7f02ac091f8b58950b2273893,sentry-public_key=0657fc27d0444b2baf05c7c3b31e7bc5,sentry-trace_id=f594d2c8c20540ca80a014b558586953,sentry-sample_rate=0.2", "Authorization": "Bearer "+token, "Referer": "https://my.exness.com/pa/", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Site": "same-origin", "Priority": "u=4", "Te": "trailers"}
        r=requests.get(burp0_url, headers=burp0_headers, timeout=30)
        data = r.json()
        balance = 0
        try:
            for elem in data:
                if elem["is_real"] == True:
                    balance = balance+float(elem["withdrawable_usd"])
        except:
            if elem["is_real"] == True:
                data[0]['withdrawable_usd']
        data={"email":email,"password":password,"balance":balance,"success":True,'personal':info}
        return data
    except requests.exceptions.Timeout:
        data = {"error": "The request timed out. Please try again later."}
    except requests.exceptions.RequestException as e:
        data = {"error": str(e)}
    return data

app = Flask(__name__)


@app.route('/')
@cross_origin()
def hello_world():
    email = request.args.get('email')
    version = request.endpoint
    password = request.args.get('password')
    #password =url_decode(password)
    #data = login(email,password)
    try:
        #token= data["token"]
        #refresh = data["refresh"]
        #data = getBalance(token,refresh,email,password)
        data= login(email,password)
        #first_name = info['first_name']
        #phone = data['security_objects'][1]['value']
        return jsonify(data)
    except:
        return jsonify({"success":False})
    #return jsonify(data)
