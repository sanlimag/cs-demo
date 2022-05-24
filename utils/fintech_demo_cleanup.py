#!/usr/bin/env python3
import argparse
import json
import uuid
import requests
import string
import re
import secrets
import bcrypt

def parse_args():
    parser = argparse.ArgumentParser(description='Create users from CSV')
    parser.add_argument('--domain', required=True, help="Environment domain")
    parser.add_argument('--user', required=True, help="Admin username")
    parser.add_argument('--password', required=True, help="Admin password")
    parser.add_argument('--noverifyssl', default=True, action="store_false", help="Optional flag for self-signed certificates")
    parser.add_argument('--teardown', default=False, action="store_true")
    return parser.parse_args()


def generate_password(length=16):
    """
    Generate a Randomized hashed password.
    """
    chars      = ''.join([string.ascii_letters, string.digits])
    pw         = ''.join(secrets.choice(chars) for token in range(length)).encode('utf-8')
    hash_value = bcrypt.hashpw(pw, bcrypt.gensalt())

    return pw.decode('utf-8'), hash_value.decode('utf-8')


def deleteSubAccount(domain, timeout, token, email):
    """
    Delete a sub account of the specified account.
    """

    response = requests.request(
        method = 'POST',
        url    = domain + '/user/deleteSubAccount',
        json   = {
            "Username": email
        },
        timeout = timeout,
        headers =  {
            "Content-Type"                : "application/json",
            "x-amz-security-token"        : token,
            "x-amz-chaossumo-route-token" : "login"
        }
    )

    if response.ok:
        jsonout = response.json()
        print(jsonout)
    else:
        jsonout = ''

def postAddUser(domain, timeout, token, email, password):
    r = requests.request(
        method = 'POST',
        url    = domain + '/user/createSubAccount',
        json   = {
            "UserInfoBlock": {
                "Username" : email,
                "FullName" : email,
                "Email"    : email,
            },
            "Password" : password,
            "Hocon"    : [
                "override.Services.worker.quota=50",
            ]
        },
        timeout = timeout,
        headers = {
            "Content-Type"                : "application/json",
            "x-amz-security-token"        : token,
            "x-amz-chaossumo-route-token" : "login"
        }
    )
    print(r.reason)
    return (r.ok, r.reason, email,)

def fetchToken(domain, tokenusername, tokenpassword):

    # Get Token
    try:
        tokenverb = "POST"
        tokenpath = "/user/login"
        tokenurl = f"{domain}{tokenpath}"
        tokenheaders = {"Content-Type": "application/json",
                        "x-amz-chaossumo-route-token": "login"}
        tokenpayload = {"Username": tokenusername,
                        "Password": tokenpassword}
        print("Sending %s %s" % (tokenverb, tokenurl))
        response = requests.request(tokenverb, tokenurl, json=tokenpayload, headers=tokenheaders, verify=verifyssl)
        print("Status code: %s" % response.status_code)
        print("Response message: %s" % response.text)
        token = json.loads(response.text)['Token']
    except Exception as ex:
        print("Failed to make request. Exception: %s" % str(ex))
        exit(1)

    return token


if __name__ == '__main__':
    args = parse_args()
    domain = args.domain
    tokenusername = args.user # Root account username
    tokenpassword = args.password # Root account password
    is_teardown = args.teardown
    verifyssl = args.noverifyssl

    token = fetchToken(domain, tokenusername, tokenpassword)

    #INSERT: ENTER_USER_NAMES_HERE:
    users = [
        "petebbonafide@gmail.com",
        "ke.wu@ampf.com"
    ]

    user_creds_dict = {}
    for user in users:
        if is_teardown:
            deleteSubAccount(domain, 120, token, user)
        else:
            password, hash = generate_password()
            postAddUser(domain, 120, token, user, password)
            user_creds_dict[user] = password

    if len(user_creds_dict) > 0:
        print(json.dumps(user_creds_dict, indent=4))