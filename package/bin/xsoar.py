#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, division, print_function, unicode_literals

__author__ = "TrackMe Limited"
__copyright__ = "Copyright 2025, TrackMe Limited, U.K."
__credits__ = "TrackMe Limited, U.K."
__license__ = "TrackMe Limited, all rights reserved"
__version__ = "0.1.0"
__maintainer__ = "TrackMe Limited, U.K."
__email__ = "support@trackme-solutions.com"
__status__ = "PRODUCTION"

# Built-in libraries
import json
import logging
import os
import sys
import time
from ast import literal_eval
from datetime import datetime, timezone
import secrets
import string
import hashlib

# Third-party libraries
import requests
import urllib3

# Logging handlers
from logging.handlers import RotatingFileHandler

# Disable insecure request warnings for urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# set logging
filehandler = RotatingFileHandler(
    "%s/var/log/splunk/xsoar.log" % splunkhome,
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()  # root logger - Good to get it only once.
for hdlr in log.handlers[:]:  # remove the existing file handlers
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)  # set the new handler
# set the log level to INFO, DEBUG as the default is ERROR
log.setLevel(logging.INFO)

# append lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-trackme-xsoar", "lib"))

# Import Splunk libs
from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)

# Import trackme libs
from xsoar_libs import xsoar_reqinfo


# get current user and roles membership
def get_user_roles(self):
    """
    Retrieve current user and his roles.
    """

    # get current user
    username = self._metadata.searchinfo.username

    # get user info
    users = self.service.users

    # Get roles for the current user
    username_roles = []
    for user in users:
        if user.name == username:
            username_roles = user.roles
    logging.debug('username="{}", roles="{}"'.format(username, username_roles))

    # return current user roles as a list
    return username_roles


def validate_url(target_type, url):
    if target_type == "splunk" and not url.startswith("/services/xsoar/"):
        error_msg = "API url is invalid and should start with: /services/xsoar/ if target is an internal Splunk API endpoint to this application"
        logging.error(error_msg)
        raise Exception(error_msg)


def prepare_request_body(body):
    try:
        return json.dumps(json.loads(body), indent=1)
    except ValueError:
        return json.dumps(literal_eval(body), indent=1)


def generate_xsoar_auth_headers(api_key_id, api_key_secret):
    """
    Generate XSOAR authentication headers according to the official API documentation.

    Args:
        api_key_id: The XSOAR API key ID
        api_key_secret: The XSOAR API key secret

    Returns:
        dict: Headers dictionary with proper XSOAR authentication
    """
    # Generate a 64 bytes random string
    nonce = "".join(
        [secrets.choice(string.ascii_letters + string.digits) for _ in range(64)]
    )

    # Get the current timestamp as milliseconds
    timestamp = int(datetime.now(timezone.utc).timestamp()) * 1000

    # Generate the auth key: api_key + nonce + timestamp
    auth_key = f"{api_key_secret}{nonce}{timestamp}"

    # Convert to bytes object and calculate sha256
    auth_key_bytes = auth_key.encode("utf-8")
    api_key_hash = hashlib.sha256(auth_key_bytes).hexdigest()

    # Generate HTTP call headers
    headers = {
        "x-xdr-timestamp": str(timestamp),
        "x-xdr-nonce": nonce,
        "x-xdr-auth-id": str(api_key_id),
        "Authorization": api_key_hash,
    }

    return headers


def xsoar_get_account(session_key, splunkd_uri, account):
    """
    Get the account information for the given account
    This performs a POST call as: "https://127.0.0.1:8089/services/xsoar/v1/get_account" -d "{\"account\": \"xsoar\"}"
    The response is a JSON object as:

    {
    "status": "success",
    "message": "xsoar get account secret was successful",
    "account": "xsoar",
    "xsoar_url": "https://api-company.us.com/xsoar/public/v1",
    "xsoar_api_keyid": "1234",
    "xsoar_api_key": "******",
    "xsoar_api_key_secret": "5678910",
    "rbac_roles": [
        "admin",
        "sc_admin",
        "trackme_user",
        "trackme_power",
        "trackme_admin"
    ],
    "xsoar_ssl_verify": "1"
    }

    Args:
        session_key: The session key to use for the request
        splunkd_uri: The URI of the Splunk server
        account: The account to get the information for

    Returns:
    """

    try:
        # get the account information
        # Splunk Cloud vetting note: this is an internal call to the splunkd API and SSL verification must be disabled
        response = requests.post(
            f"{splunkd_uri}/services/xsoar/v1/get_account",
            headers={"Authorization": f"Splunk {session_key}"},
            data=json.dumps({"account": account}),
            verify=False,
        )

        # raise an exception if the response is not successful
        if not response.ok:
            raise Exception(
                f"Failed to get account information, status_code={response.status_code}, response_text={response.text}"
            )

        # parse the response
        response_json = response.json()

        return response_json

    except Exception as e:
        logging.error(f"Error in xsoar_get_account: {e}")
        raise Exception(f"Failed to get account information, error={e}")


@Configuration(distributed=False)
class xsoarRestHandler(GeneratingCommand):

    target_type = Option(
        doc=""" **Syntax:** **The target_type=**** **Description:** Mandatory, the target type, either 'splunk' or 'xsoar'""",
        require=False,
        default="xsoar",
        validate=validators.Match("target_type", r"^(?:splunk|xsoar)$"),
    )

    url = Option(
        doc=""" **Syntax:** **The endpoint URL=**** **Description:** Mandatory, the endpoint URL""",
        require=True,
        default=None,
        validate=validators.Match("url", r"^.*"),
    )

    account = Option(
        doc=""" **Syntax:** **The xsoar account=**** **Description:** Mandatory if running a call against the xsoar API""",
        require=False,
        default=None,
        validate=validators.Match("account", r"^.*$"),
    )

    mode = Option(
        doc=""" **Syntax:** **The HTTP mode=**** **Description:** Optional, the HTTP mode to be used for the REST API call""",
        require=False,
        default="get",
        validate=validators.Match("mode", r"^(?:get|post|delete)$"),
    )

    body = Option(
        doc=""" **Syntax:** **The HTTP body data=**** **Description:** Optional, the HTTP data to be used for the REST API call, optional for get and mandatory for post/delete calls""",
        require=False,
        default=None,
    )

    def generate(self, **kwargs):
        start = time.time()
        error_message = None

        try:
            # set default logging to INFO
            log.setLevel(logging.INFO)

            # get reqinfo
            reqinfo = xsoar_reqinfo(
                logging,
                self._metadata.searchinfo.session_key,
                self._metadata.searchinfo.splunkd_uri,
            )

            # set logging_level
            log.setLevel(reqinfo["logging_level"])

            # init headers
            headers = {}

            # session key
            session_key = self._metadata.searchinfo.session_key

            # earliest & latest
            earliest = self._metadata.searchinfo.earliest_time
            latest = self._metadata.searchinfo.latest_time
            timerange = float(latest) - float(earliest)

            # identify target_type
            validate_url(self.target_type, self.url)

            if self.target_type == "xsoar":
                if not self.account:
                    raise Exception("Account is mandatory for xsoar target_type")

                try:
                    account_info = xsoar_get_account(
                        self._metadata.searchinfo.session_key,
                        self._metadata.searchinfo.splunkd_uri,
                        self.account,
                    )
                except Exception as e:
                    logging.error(f"Error in xsoar_get_account: {e}")
                    raise Exception(f"Failed to get account information, exception={e}")

                # RBAC
                rbac_roles = account_info.get("rbac_roles")

                # check RBAC
                user_roles = get_user_roles(self)
                rbac_granted = False

                for user_role in user_roles:
                    if user_role in rbac_roles:
                        rbac_granted = True
                        break

                # grant the system user
                if self._metadata.searchinfo.username in (
                    "splunk-system-user",
                    "admin",
                ):
                    rbac_granted = True

                if not rbac_granted:
                    logging.debug(
                        f'RBAC access not granted to this account, user_roles="{user_roles}", account_roles="{rbac_roles}", username="{self._metadata.searchinfo.username}"'
                    )
                    raise Exception(
                        "Access to this account has been refused, please contact your TrackMe administrator to grant access to this account"
                    )
                else:
                    logging.debug(
                        f'RBAC access granted to this account, user_roles="{user_roles}", account_roles="{rbac_roles}"'
                    )

                # Generate proper XSOAR authentication headers
                api_key_id = account_info.get("xsoar_api_keyid")
                api_key_secret = account_info.get("xsoar_api_key_secret")

                if not api_key_id or not api_key_secret:
                    raise Exception(
                        "XSOAR API key ID or secret not found in account configuration"
                    )

                xsoar_headers = generate_xsoar_auth_headers(api_key_id, api_key_secret)
                headers.update(xsoar_headers)

                target_url = f'{account_info.get("xsoar_url")}/{self.url.lstrip("/")}'
                logging.debug(f"target_url={target_url}")

                # ssl verification
                xsoar_ssl_verify = int(account_info.get("xsoar_ssl_verify", 1))

                if xsoar_ssl_verify == 0:
                    verify_ssl = False
                else:
                    verify_ssl = True

            elif self.target_type == "splunk":
                headers["Authorization"] = f"Splunk {session_key}"
                target_url = (
                    f"{self._metadata.searchinfo.splunkd_uri}/{self.url.lstrip('/')}"
                )
                # Internal communication with splunkd on the loopback, must not verify
                verify_ssl = False

            else:
                raise Exception(f"Unsupported target_type: {self.target_type}")

            if self.body:
                if self.target_type == "splunk":
                    # For Splunk endpoints, send as JSON (the REST API expects JSON in payload)
                    try:
                        # Parse the JSON body and send as JSON string
                        body_dict = json.loads(self.body)
                        json_data = json.dumps(body_dict)
                        headers["Content-Type"] = "application/json"
                    except ValueError:
                        # Fallback to literal_eval if json.loads fails
                        body_dict = literal_eval(self.body)
                        json_data = json.dumps(body_dict)
                        headers["Content-Type"] = "application/json"
                else:
                    # For XSOAR endpoints, send as JSON
                    json_data = prepare_request_body(self.body)
                    headers["Content-Type"] = "application/json"
            else:
                json_data = None

            #
            # free API call
            #

            if self.mode == "get":
                logging.info(f"GET {target_url}")
                response = requests.get(target_url, headers=headers, verify=verify_ssl)
            elif self.mode == "post":
                logging.info(f"POST {target_url}, data={json_data}")
                response = requests.post(
                    target_url, headers=headers, data=json_data, verify=verify_ssl
                )
            elif self.mode == "delete":
                logging.info(f"DELETE {target_url}, data={json_data}")
                response = requests.delete(
                    target_url, headers=headers, data=json_data, verify=verify_ssl
                )
            else:
                raise Exception(f"Unsupported mode: {self.mode}")

            # raise an exception if the response is not successful
            response.raise_for_status()

            # parse the response
            try:
                response_json = response.json()
                logging.debug(
                    f"response.status_code={response.status_code}, response.text={response.text}"
                )

                result = {
                    "_time": time.time(),
                    "_raw": response_json,
                }
                yield result

            except json.JSONDecodeError:

                # If the response isn't valid JSON, return the plain text of the response
                logging.debug(
                    f"response is plain text, attempting to detect JSON in response"
                )

                result = {
                    "_time": time.time(),
                    "_raw": response.text,
                }
                yield result

            # Log the run time
            logging.info(
                f"xsoar API command has terminated, response is logged in debug mode only, run_time={round(time.time() - start, 3)}"
            )

        except Exception as e:
            error_message = str(e)
            logging.error(f"Error in xsoar API command: {error_message}")
            raise e


dispatch(xsoarRestHandler, sys.argv, sys.stdin, sys.stdout, __name__)
