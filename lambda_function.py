#!/usr/bin/env python
#
# *******************************************************************************
# Name: lambda_function.py
# Version: v1.1
# Description: This open source AWS tool consumes the published security findings detected in Radware CWP to then
# trigger an event in Microsoft Azure Sentinel. The CWP Findings passed to Microsoft Azure Sentinel are determined by the CWP risk
# score filter within the tool. All other findings are discarded.
#
# Author: Chen Sagi
# www.radware.com
#
# Environment Variables required:
#  - shared_key
#  - customer_id
#  - cwp_score_filter
# *******************************************************************************

import os
import json
import requests
import datetime
import hashlib
import hmac
import base64

# declare variables
shared_key = os.environ['shared_key']
customer_id = os.environ['customer_id']
cwp_score_filter = os.environ['cwp_score_filter']
cwp_score_filter = cwp_score_filter.split(',')

log_type = "RadwareCNP"

# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")  
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization

# Build and send a request to the POST API
def post_data(customer_id, shared_key, body, log_type):
    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    content_length = len(body)
    signature = build_signature(customer_id, shared_key, rfc1123date, content_length, method, content_type, resource)
    uri = 'https://' + customer_id + '.ods.opinsights.azure.com' + resource + '?api-version=2016-04-01'

    headers = {
        'content-type': content_type,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }

    response = requests.post(uri,data=body, headers=headers)
    if (response.status_code >= 200 and response.status_code <= 299):
        print('Accepted')
    else:
        raise Exception("Response code: {}".format(response.status_code))

def process_alert(msg):
    # determine if event meets required alert threshold
    if msg["score"] in cwp_score_filter:
        # Alert objectType considerations for differences in metadata
        if msg["objectType"] == 'Alert':
            summary = msg["title"]
            timestamp = msg["createdDate"]
            custom_details = {
              "Event Type": "Alert",
              "Risk Score": msg["score"]
            }
        elif msg["objectType"] == 'WarningEntity':
            summary = msg["subject"]
            timestamp = msg["lastDetectionDate"]
            custom_details = {
                "Event Type": "Warning",
                "Account Name": msg["accountName"],
                "Risk Score": msg["score"],
                "Warning Description": msg["description"],
                "Recommendation": msg["recommendation"],
                "Resource Type": msg["resourceType"]
            }
        else:
            process_error = f'Alert (objectType) not supported: {msg["objectType"]}'
            print(process_error)
            return {"success": False, "comment": process_error}

        links = [{"href": msg["objectPortalURL"], "text": "Link to event in Radware CNP Portal"}]

        payload = {
            "summary": summary,
            "source": f'{msg["accountVendor"]}:{msg["accountIds"][0]}',
            "timestamp": timestamp,
            "group": msg["accountIds"][0],
            "custom_details": custom_details
        }

        # post event data to Azure Analytics
        post_data(customer_id, shared_key, json.dumps(payload), log_type)

        # write report
        report = {"success": True, "eventType": msg["objectType"], "riskScore": msg["score"], "comment": ""}
        return report
    else:
        report = {"success": False, "eventType": msg["objectType"], "riskScore": msg["score"], "comment": "Discarded. Risk score did not meet threshold requirements."}
        return report


def lambda_handler(event, context):
    message = event['Records'][0]['Sns']['Message']
    ## uncomment the following for debugging
    #print("From SNS: " + str(message))
    message = json.loads(message)
    report = process_alert(message)

    print(report)
    return report
