#!/usr/bin/env python

# Script used to create a login URL to a client's
# AWS console.
# Requires 3 parameters: 
#   1. Target Account ID = Provided by client.  ACCNT_AWS_ACCOUNT_ID in trackor.onevizion.com
#   2. Name of the role to assume = Provided by client.  ACCNT_AWS_ROLE in trackor.onevizion.com
#   3. External ID for target account = XITOR_ID of Account in trackor.onevizion.com

import requests # "pip install requests"
import sys, os, urllib, json, webbrowser
import subprocess
import onevizion 
from boto.sts import STSConnection # AWS Python SDK--"pip install boto"

# Handle command arguments
import argparse
Description="""
"""
EpiLog = onevizion.PasswordExample + """\n\n
"""
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description=Description,epilog=EpiLog)
parser.add_argument("Account", help="The OneVizion Client Account name from trackor.  Example: Mobilitie")
parser.add_argument("-v", "--verbose", action='count', default=0, help="Print extra debug messages and save to a file. Attach file to email if sent.")
parser.add_argument("-p", "--passwords", metavar="PasswordsFile", help="JSON file where passwords are stored.", default="Passwords.json")
args = parser.parse_args()
PasswordsFile = args.passwords

Account = args.Account

# Load in Passwords from protected file.
PasswordData = onevizion.GetParameters(PasswordsFile)
# Make sure Passwordsfile has correct sections
PDError = (
    onevizion.CheckPasswords(PasswordData,'trackor.onevizion.com',['UserName','Password'])
    )
if len(PDError) > 0:
    print PDError
    quit()


AccountInfo = onevizion.Trackor(
    trackorType = 'Accounts', 
    URL = 'trackor.onevizion.com', 
    userName=PasswordData['trackor.onevizion.com']["UserName"], 
    password=PasswordData['trackor.onevizion.com']["Password"]
    )
AccountInfo.read(
    filters={
        "TRACKOR_KEY":Account
        },
    fields=[
        'ACCNT_AWS_ACCOUNT_ID',
        'ACCNT_AWS_ROLE',
        'ACCNT_EXTERNAL_ID'
        ]
    )

if len(AccountInfo.errors) > 0:
    print str(AccountInfo.errors)
    print str(AccountInfo.OVCall.request.status_code)+" = "+AccountInfo.OVCall.request.reason+"\n"+AccountInfo.OVCall.request.text
    quit()


 
# Step1: Prompt user for target account ID, name of role to assume 
# and External ID for target account
account_id_from_user = AccountInfo.jsonData[0]['ACCNT_AWS_ACCOUNT_ID']
role_name_from_user = AccountInfo.jsonData[0]['ACCNT_AWS_ROLE']
external_id_from_user = AccountInfo.jsonData[0]['ACCNT_EXTERNAL_ID']

print account_id_from_user
print role_name_from_user
print external_id_from_user

#quit() 
# Create an ARN out of the information provided by the user.
role_arn = "arn:aws:iam::" + account_id_from_user + ":role/"
role_arn += role_name_from_user
 
# Step 2: Connect to AWS STS and then call AssumeRole. This returns 
# temporary security credentials.
sts_connection = STSConnection()
assumed_role_object = sts_connection.assume_role(
    role_arn=role_arn,
    role_session_name="AssumeRoleSession",
    external_id=external_id_from_user
)
 
# Step 3: Format resulting temporary credentials into a JSON block using 
# known field names.
access_key = assumed_role_object.credentials.access_key
session_key = assumed_role_object.credentials.secret_key
session_token = assumed_role_object.credentials.session_token
json_temp_credentials = '{'
json_temp_credentials += '"sessionId":"' + access_key + '",'
json_temp_credentials += '"sessionKey":"' + session_key + '",'
json_temp_credentials += '"sessionToken":"' + session_token + '"'
json_temp_credentials += '}'
 
# Step 4. Make a request to the AWS federation endpoint to get a sign-in 
# token, passing parameters in the query string. The call requires an 
# Action parameter ('getSigninToken') and a Session parameter (the  
# JSON string that contains the temporary credentials that have 
# been URL-encoded).
request_parameters = "?Action=getSigninToken"
request_parameters += "&Session="
request_parameters += urllib.quote_plus(json_temp_credentials)
request_url = "https://signin.aws.amazon.com/federation"
request_url += request_parameters
r = requests.get(request_url)
 
# Step 5. Get the return value from the federation endpoint--a 
# JSON document that has a single element named 'SigninToken'.
sign_in_token = json.loads(r.text)["SigninToken"]
 
# Step 6: Create the URL that will let users sign in to the console using 
# the sign-in token. This URL must be used within 15 minutes of when the
# sign-in token was issued.
request_parameters = "?Action=login"
request_parameters += "&Issuer="
request_parameters += "&Destination="
request_parameters += urllib.quote_plus("https://console.aws.amazon.com/")
request_parameters += "&SigninToken=" + sign_in_token
request_url = "https://signin.aws.amazon.com/federation"
request_url += request_parameters
 
# Step 7: Use the default browser to sign in to the console using the
# generated URL.
print request_url

if sys.platform=='win32':
    os.startfile(request_url)
elif sys.platform=='darwin':
    subprocess.Popen(['open', request_url])



