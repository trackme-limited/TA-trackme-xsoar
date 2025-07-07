#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "TrackMe Limited"
__copyright__ = "Copyright 2023, TrackMe Limited, U.K."
__credits__ = "TrackMe Limited, U.K."
__license__ = "TrackMe Limited, all rights reserved"
__version__ = "0.1.0"
__maintainer__ = "TrackMe Limited, U.K."
__email__ = "support@trackme-solutions.com"
__status__ = "PRODUCTION"

# Standard library imports
import os
import sys
import re
import json
import logging

# Networking and URL handling imports
import requests
from requests.structures import CaseInsensitiveDict
from urllib.parse import urlencode
import urllib3

# Disable insecure request warnings for urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# appebd lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-trackme-xsoar", "lib"))

# import Splunk libs
import splunklib.client as client
import splunklib.results as results

# logging:
# To avoid overriding logging destination of callers, the libs will not set on purpose any logging definition
# and rely on callers themselves


def xsoar_reqinfo(logger, session_key, splunkd_uri):
    """
    Retrieve request info & settings.
    """

    # Ensure splunkd_uri starts with "https://"
    if not splunkd_uri.startswith("https://"):
        splunkd_uri = f"https://{splunkd_uri}"

    # Build header and target URL
    headers = CaseInsensitiveDict()
    headers["Authorization"] = f"Splunk {session_key}"
    target_url = f"{splunkd_uri}/services/xsoar/v1/request_info"

    # Create a requests session for better performance
    session = requests.Session()
    session.headers.update(headers)

    try:
        # Use a context manager to handle the request
        with session.get(target_url, verify=False) as response:
            if response.ok:
                logger.debug(f'Success retrieving conf, data="{response}"')
                response_json = response.json()
                return response_json
            else:
                error_message = f'Failed to retrieve conf, status_code={response.status_code}, response_text="{response.text}"'
                logger.error(error_message)
                raise Exception(error_message)

    except Exception as e:
        error_message = f'Failed to retrieve conf, exception="{str(e)}"'
        logger.error(error_message)
        raise Exception(error_message)


def xsoar_getloglevel(logger, system_authtoken, splunkd_port):
    """
    Simply get and return the loglevel with elevated privileges to avoid code duplication
    """

    # Get service
    service = client.connect(
        owner="nobody",
        app="TA-trackme-xsoar",
        port=splunkd_port,
        token=system_authtoken,
    )

    # set loglevel
    loglevel = "INFO"
    conf_file = "ta_trackme_xsoar_settings"
    confs = service.confs[str(conf_file)]
    for stanza in confs:
        if stanza.name == "logging":
            for stanzakey, stanzavalue in stanza.content.items():
                if stanzakey == "loglevel":
                    loglevel = stanzavalue

    return loglevel


def get_xsoar_secret(logger, storage_passwords, account):
    # realm
    credential_realm = (
        "__REST_CREDENTIAL__#TA-trackme-xsoar#configs/conf-ta_trackme_xsoar_account"
    )
    credential_name = f"{credential_realm}:{account}``"

    # extract as raw json
    bearer_token_rawvalue = ""

    for credential in storage_passwords:
        if credential.content.get("realm") == str(
            credential_realm
        ) and credential.name.startswith(credential_name):
            bearer_token_rawvalue = bearer_token_rawvalue + str(
                credential.content.clear_password
            )

    # extract a clean json object
    bearer_token_rawvalue_match = re.search(
        '\{"xsoar_api_key":\s*"(.*)"\}', bearer_token_rawvalue
    )
    if bearer_token_rawvalue_match:
        bearer_token = bearer_token_rawvalue_match.group(1)
    else:
        logger.error(f"Failed to retrieve xsoar api key secret, account={account}")
        bearer_token = None

    return bearer_token


# Get account credentials, designed to be used for a least privileges approach in a programmatic approach
def xsoar_get_account(logger, reqinfo, account):
    # get service
    service = client.connect(
        owner="nobody",
        app="TA-trackme-xsoar",
        port=reqinfo.server_rest_port,
        token=reqinfo.system_authtoken,
    )

    # Splunk credentials store
    storage_passwords = service.storage_passwords

    # get all acounts
    accounts = []
    conf_file = "ta_trackme_xsoar_account"

    # if there are no account, raise an exception, otherwise what we would do here?
    try:
        confs = service.confs[str(conf_file)]
    except Exception as e:
        error_msg = "We have no remote account configured yet"
        raise Exception(error_msg)

    for stanza in confs:
        # get all accounts
        for name in stanza.name:
            accounts.append(stanza.name)
            break

    # Initialization
    isfound = False
    keys_mapping = {
        "xsoar_url": None,
        "xsoar_api_keyid": None,
        "xsoar_api_key": None,
        "rbac_roles": None,
        "xsoar_ssl_verify": None,
    }

    # Get account
    for stanza in confs:
        if stanza.name == str(account):
            isfound = True
            for key, value in stanza.content.items():
                if key in keys_mapping:
                    keys_mapping[key] = value
            break  # Exit loop once the account is found

    # Assign variables
    xsoar_url = keys_mapping["xsoar_url"]
    xsoar_api_keyid = keys_mapping["xsoar_api_keyid"]
    xsoar_api_key = keys_mapping["xsoar_api_key"]
    rbac_roles = keys_mapping["rbac_roles"]
    xsoar_ssl_verify = keys_mapping["xsoar_ssl_verify"]

    # end of get configuration

    # Stop here if we cannot find the submitted account
    if not isfound:
        error_msg = f'The account "{account}" was not found configured in this system, please check your input.'
        raise Exception(
            {
                "status": "failure",
                "message": error_msg,
                "account": account,
            }
        )

    # RBAC
    rbac_roles = rbac_roles.split(",")

    # get the secret
    xsoar_api_key_secret = get_xsoar_secret(logger, storage_passwords, account)

    try:
        return {
            "status": "success",
            "message": "xsoar get account secret was successful",
            "account": account,
            "xsoar_url": xsoar_url,
            "xsoar_api_keyid": xsoar_api_keyid,
            "xsoar_api_key": xsoar_api_key,
            "xsoar_api_key_secret": xsoar_api_key_secret,
            "rbac_roles": rbac_roles,
            "xsoar_ssl_verify": xsoar_ssl_verify,
        }

    except Exception as e:
        error_msg = f'The xsoar token for the account="{account}" could not be retrieved, exception={str(e)}'
        raise Exception(
            {
                "status": "failure",
                "message": error_msg,
                "account": account,
            }
        )
