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
    "%s/var/log/splunk/xsoarresilient.log" % splunkhome,
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
    elif target_type == "xsoar" and not url.startswith("/api/"):
        error_msg = "API url is invalid and should start with: /api/ when target is a xsoar API endpoint"
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


def get_kv_collection(
    collection,
    collection_name,
):
    """
    Get all records from a KVstore collection.

    :param collection: The KVstore collection object.
    :param collection_name: The name of the collection to query.

    :return: A tuple containing the records, keys, and a dictionary of the records.
    """
    collection_records = []
    collection_records_keys = set()
    collection_dict = {}

    end = False
    skip_tracker = 0
    while end == False:
        process_collection_records = collection.data.query(skip=skip_tracker, limit=500)
        if len(process_collection_records) != 0:
            for item in process_collection_records:
                if item.get("_key") not in collection_records_keys:
                    collection_records.append(item)
                    collection_records_keys.add(item.get("_key"))
                    collection_dict[item.get("_key")] = item
            skip_tracker += 500
        else:
            end = True

    return collection_records, collection_records_keys, collection_dict


@Configuration(distributed=False)
class xsoarRestHandler(GeneratingCommand):

    run_mode = Option(
        doc=""" **Syntax:** **The run mode, either 'live' or 'simulate', in simulate mode the request is not sent to the XSOAR API""",
        require=False,
        default="live",
        validate=validators.Match("mode", r"^(?:live|simulate)$"),
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

            logging.debug(f"reqinfo={json.dumps(reqinfo)}")

            # set logging_level
            log.setLevel(reqinfo["logging_level"])

            # session key
            session_key = self._metadata.searchinfo.session_key

            # get the enable_resilient_store
            enable_resilient_store = int(
                reqinfo["ta_trackme_xsoar_conf"]["resilient_store"][
                    "enable_resilient_store"
                ]
            )

            # turn int to a boolean
            enable_resilient_store = bool(enable_resilient_store)

            # exit immediately if the resilient store is not enabled
            if not enable_resilient_store:
                logging.info(f"Resilient store is not enabled, nothing to do.")
                yield {
                    "_time": time.time(),
                    "message": f"Resilient store is not enabled, nothing to do.",
                    "_raw": {
                        "message": f"Resilient store is not enabled, nothing to do.",
                    },
                }
                return True

            # from reqinfo, get the max_attempts
            max_attempts = int(
                reqinfo["ta_trackme_xsoar_conf"]["resilient_store"]["max_attempts"]
            )

            # earliest & latest
            earliest = self._metadata.searchinfo.earliest_time
            latest = self._metadata.searchinfo.latest_time
            timerange = float(latest) - float(earliest)

            # connect to the resilient store
            collection_name = "kv_xsoar_resilient_store"
            collection = self.service.kvstore[collection_name]

            # get the collection records
            collection_records, collection_records_keys, collection_dict = (
                get_kv_collection(collection, collection_name)
            )

            if not collection_records:
                logging.info(
                    f'No records found in the resilient store, collection_name="{collection_name}", nothing to do.'
                )
                yield {
                    "_time": time.time(),
                    "message": f'No records found in the resilient store, collection_name="{collection_name}", nothing to do.',
                    "_raw": {
                        "message": f'No records found in the resilient store, collection_name="{collection_name}", nothing to do.',
                    },
                }
                return True

            else:

                # process the collection records
                for record in collection_records:
                    logging.info(f'Processing record, record="{record}"')

                    # init headers
                    headers = {"Content-Type": "application/json"}

                    # get our fields (account, transaction_id, request_endpoint, request_method, request_body)
                    account = record.get("account")
                    transaction_id = record.get("transaction_id")
                    request_endpoint = record.get("request_endpoint")
                    request_method = record.get("request_method")
                    request_body = record.get("request_body")
                    ctime = record.get("ctime")
                    mtime = record.get("mtime")
                    no_attempts = int(record.get("no_attempts", 1))
                    last_error = record.get("last_error")

                    # load the request body
                    try:
                        request_body = json.loads(request_body)
                    except ValueError:
                        logging.error(
                            f'Error loading the request body, transaction_id="{transaction_id}", account="{account}", request_body="{request_body}"'
                        )
                        continue

                    # get the account information
                    try:
                        account_info = xsoar_get_account(
                            self._metadata.searchinfo.session_key,
                            self._metadata.searchinfo.splunkd_uri,
                            self.account,
                        )
                    except Exception as e:
                        logging.error(f"Error in xsoar_get_account: {e}")
                        raise Exception(
                            f"Failed to get account information, exception={e}"
                        )

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

                    #
                    # max attempts verification:
                    # - if max_attempts is reached, delete the record from the resilient store
                    #

                    logging.debug(
                        f'no_attempts="{no_attempts}", max_attempts="{max_attempts}"'
                    )

                    if no_attempts >= max_attempts:
                        logging.info(
                            f'Max attempts reached, deleting the record from the resilient store, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}"'
                        )
                        if not self.run_mode == "simulate":
                            try:
                                collection.data.delete(
                                    json.dumps({"_key": transaction_id})
                                )
                                logging.info(
                                    f'Successfully deleted the record from the resilient store, transaction_id="{transaction_id}"'
                                )
                                yield {
                                    "_time": time.time(),
                                    "transaction_id": transaction_id,
                                    "account": account,
                                    "request_endpoint": request_endpoint,
                                    "request_method": request_method,
                                    "response_status": "failed",
                                    "response_text": f'Max attempts reached, deleting the record from the resilient store, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}"',
                                    "_raw": {
                                        "transaction_id": transaction_id,
                                        "account": account,
                                        "request_endpoint": request_endpoint,
                                        "request_method": request_method,
                                        "response_status": "failed",
                                        "response_text": f'Max attempts reached, deleting the record from the resilient store, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}"',
                                    },
                                }
                            except Exception as e:
                                logging.error(
                                    f'Error deleting the record from the resilient store, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}", error="{e}"'
                                )
                                yield {
                                    "_time": time.time(),
                                    "transaction_id": transaction_id,
                                    "account": account,
                                    "request_endpoint": request_endpoint,
                                    "request_method": request_method,
                                    "response_status": "failed",
                                    "response_text": f'Error deleting the record from the resilient store, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}", error="{e}"',
                                    "_raw": {
                                        "transaction_id": transaction_id,
                                        "account": account,
                                        "request_endpoint": request_endpoint,
                                        "request_method": request_method,
                                        "response_status": "failed",
                                        "response_text": f'Error deleting the record from the resilient store, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}", error="{e}"',
                                    },
                                }
                            continue

                    # Generate proper XSOAR authentication headers
                    api_key_id = account_info.get("xsoar_api_keyid")
                    api_key_secret = account_info.get("xsoar_api_key_secret")

                    if not api_key_id or not api_key_secret:
                        raise Exception(
                            "XSOAR API key ID or secret not found in account configuration"
                        )

                    xsoar_headers = generate_xsoar_auth_headers(
                        api_key_id, api_key_secret
                    )
                    headers.update(xsoar_headers)

                    target_url = f'{account_info.get("xsoar_url")}/{request_endpoint.lstrip("/")}'
                    logging.debug(f"target_url={target_url}")

                    # ssl verification
                    xsoar_ssl_verify = int(account_info.get("xsoar_ssl_verify", 1))

                    if xsoar_ssl_verify == 0:
                        verify_ssl = False
                    else:
                        verify_ssl = True

                    # make the request, if the request is successful, we can delete the record from the resilient store
                    # if the request fails, increment the no_attempts, update last_error and mtime

                    if self.run_mode == "simulate":
                        yield {
                            "_time": time.time(),
                            "transaction_id": transaction_id,
                            "account": account,
                            "request_endpoint": request_endpoint,
                            "request_method": request_method,
                            "request_body": request_body,
                            "response_status": "simulated",
                            "_raw": {
                                "transaction_id": transaction_id,
                                "account": account,
                                "request_endpoint": request_endpoint,
                                "request_method": request_method,
                                "request_body": request_body,
                                "response_status": "simulated",
                            },
                        }
                        continue

                    try:
                        if request_method == "POST":
                            response = requests.post(
                                target_url,
                                headers=headers,
                                data=request_body,
                                verify=verify_ssl,
                            )
                        elif request_method == "DELETE":
                            response = requests.delete(
                                target_url,
                                headers=headers,
                                data=request_body,
                                verify=verify_ssl,
                            )
                        else:
                            raise Exception(
                                f'Unsupported request method, request_method="{request_method}"'
                            )

                        response.raise_for_status()

                        # log
                        logging.info(
                            f'Successfully processed the request, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}"'
                        )

                        # delete the record from the resilient store
                        collection.data.delete(transaction_id)

                        # yield
                        yield {
                            "_time": time.time(),
                            "transaction_id": transaction_id,
                            "account": account,
                            "request_endpoint": request_endpoint,
                            "request_method": request_method,
                            "response_status": response.status_code,
                            "response_text": response.text,
                            "message": f'Successfully processed the request, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}"',
                            "_raw": {
                                "transaction_id": transaction_id,
                                "account": account,
                                "request_endpoint": request_endpoint,
                                "request_method": request_method,
                                "response_status": response.status_code,
                                "response_text": response.text,
                                "message": f'Successfully processed the request, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}"',
                            },
                        }

                    except Exception as e:
                        logging.error(
                            f'Error in xsoar API call, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}", error="{e}"'
                        )
                        # increment the no_attempts
                        no_attempts += 1
                        # update the last_error
                        last_error = str(e)
                        # update the mtime
                        mtime = time.time()

                        # update the record
                        record["no_attempts"] = no_attempts
                        record["last_error"] = last_error
                        record["mtime"] = mtime

                        # update the record in the resilient store
                        collection.data.update(transaction_id, json.dumps(record))

                        # yield
                        yield {
                            "_time": time.time(),
                            "transaction_id": transaction_id,
                            "account": account,
                            "request_endpoint": request_endpoint,
                            "request_method": request_method,
                            "response_status": "failed",
                            "response_text": str(e),
                            "no_attempts": no_attempts,
                            "message": f'Error in xsoar API call, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}", error="{e}"',
                            "_raw": {
                                "transaction_id": transaction_id,
                                "account": account,
                                "request_endpoint": request_endpoint,
                                "request_method": request_method,
                                "response_status": "failed",
                                "response_text": str(e),
                                "no_attempts": no_attempts,
                                "message": f'Error in xsoar API call, transaction_id="{transaction_id}", account="{account}", request_endpoint="{request_endpoint}", request_method="{request_method}", request_body="{request_body}", error="{e}"',
                            },
                        }

            # Log the run time
            logging.info(
                f"xsoar API command has terminated, response is logged in debug mode only, run_time={round(time.time() - start, 3)}"
            )

        except Exception as e:
            error_message = str(e)
            logging.error(f"Error in xsoar API command: {error_message}")
            raise e


dispatch(xsoarRestHandler, sys.argv, sys.stdin, sys.stdout, __name__)
