import io
import json
import logging
import os
import requests
import hashlib
import datetime
import hmac
import base64
from fdk import response

"""
See https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
See https://blogs.oracle.com/cloud-infrastructure/post/using-microsoft-azure-sentinel-siem-tools-with-oci-logging-service
"""

# Azure Log Analytics workspace ID
workspace_id = os.getenv('AZURE_WORKSPACE_ID', 'not-configured')

# Azure Log Analytics workspace primary or secondary key
workspace_key = os.getenv('AZURE_WORKSPACE_KEY', 'not-configured')

#  Azure Log Analytics workspace name of target custom log table
workspace_table = os.getenv('AZURE_WORKSPACE_TABLE', 'OCI_DEFAULT')

# --------------------------------------------
# Functions
# --------------------------------------------



def post_to_azure(body_bytes: bytes):
    """
    Post payload per API contract.
    See https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api

    :param body_bytes:  Message to be sent.
    :return: None
    """

    content_length = len(body_bytes)
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_api_signature(content_length=content_length, rfc1123date=rfc1123date)
    uri = 'https://' + workspace_id + '.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'

    headers = {
        'content-type': 'application/json',
        'Authorization': signature,
        'Log-Type': workspace_table,
        'x-ms-date': rfc1123date
    }

    logging.debug('uri / {}'.format(uri))
    logging.debug('Azure workspace table destination / {}'.format(workspace_table))
    logging.debug('content_length / {}'.format(content_length))

    response = requests.post(uri, data=body_bytes, headers=headers)

    if (response.status_code >= 200 and response.status_code <= 299):
        logging.info('Azure Accepted')
    else:
        logging.error("Response code: {}".format(response.status_code))
        logging.error("Response text: {}".format(response.text))


def build_api_signature(content_length: int, rfc1123date: str):
    """
    Build the API signature
    See https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
    See https://docs.microsoft.com/en-us/dotnet/api/system.globalization.datetimeformatinfo.rfc1123pattern

    :param content_length: length of payload
    :param rfc1123date: date in RFC-1123 string format
    :return: signature
    """

    method = 'POST'
    content_type = 'application/json'
    resource = '/api/logs'

    x_headers = 'x-ms-date:' + rfc1123date
    string_to_hash = method + "\n" + str(content_length) + "\n" + content_type + "\n" + x_headers + "\n" + resource
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(workspace_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(workspace_id, encoded_hash)
    return authorization

