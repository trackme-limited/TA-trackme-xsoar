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
import re
from ast import literal_eval
from datetime import datetime, timezone
import secrets
import string
import hashlib
import uuid

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
    "%s/var/log/splunk/xsoarstreamincident.log" % splunkhome,
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
    StreamingCommand,
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


def get_uuid():
    """
    Function to return a unique uuid which is used to trace performance run_time of each subtask.
    """
    return str(uuid.uuid4())


def store_in_resilient_store(
    self,
    collection_name,
    collection,
    request_endpoint,
    request_method,
    request_body,
    last_error,
):
    """
    Function to store the request in the resilient KVstore if the request call has failed.
    We will store with the following concept:
    - _key: generate a random uuid
    - account: the account name
    - transaction_id: same as the _key
    - request_endpoint: the endpoint of the request
    - request_method: the method of the request
    - request_body: the body of the request
    - status: failed (static)
    - last_error: the error message of the request
    """

    # generate a random uuid
    transaction_id = get_uuid()

    # define the record
    record = {
        "_key": transaction_id,
        "account": self.account,
        "transaction_id": transaction_id,
        "request_endpoint": request_endpoint,
        "request_method": request_method,
        "request_body": json.dumps(request_body),
        "status": "failed",
        "ctime": time.time(),
        "mtime": time.time(),
        "no_attempts": 1,
        "last_error": last_error,
    }

    try:
        collection.data.insert(json.dumps(record))
        logging.info(
            f'Successfully stored the record in the resilient store, account="{self.account}", transaction_id="{transaction_id}", collection_name="{collection_name}"'
        )

    except Exception as e:
        logging.error(
            f'Error storing the record in the resilient store, account="{self.account}", transaction_id="{transaction_id}", collection_name="{collection_name}", error="{e}"'
        )

    return transaction_id


def replace_tokens(command, event_data):
    """
    Function to replace tokens in a command string with actual values from event data.
    Tokens can be in the format $result.<fieldname>$ or $<fieldname>$

    Args:
        command: The command string containing tokens to replace
        event_data: The event data dictionary containing values to use for replacement

    Returns:
        The command string with tokens replaced by their corresponding values
    """
    if not command or not event_data:
        return command

    # Pattern to match $result.<fieldname>$ or $<fieldname>$
    pattern = r"\$result\.([^$]+)\$|\$([^$]+)\$"

    def replace_match(match):
        # Get the field name from either capture group
        field_name = match.group(1) or match.group(2)

        # Try to get the value from event_data
        try:
            # Handle nested fields with dot notation
            value = event_data
            for part in field_name.split("."):
                value = value[part]
            return str(value)
        except (KeyError, TypeError):
            # If field not found or value is None, return the original token unchanged
            return match.group(0)

    # Replace all matches in the command
    return re.sub(pattern, replace_match, command)


def get_token_value(option_value, record):
    """
    Get the actual value for an option, handling token replacement if needed.

    Args:
        option_value: The option value which may contain tokens
        record: The current record containing field values

    Returns:
        The resolved value with tokens replaced, or the original value if no tokens
    """
    if not option_value:
        return option_value

    # Check if the value contains any token patterns
    if re.search(r"\$[^$]+\$", option_value):
        return replace_tokens(option_value, record)

    return option_value


@Configuration(distributed=False)
class xsoarRestHandler(StreamingCommand):

    account = Option(
        doc=""" **Syntax:** **The xsoar account=**** **Description:** Mandatory if running a call against the xsoar API""",
        require=False,
        default=None,
        validate=validators.Match("account", r"^.*$"),
    )

    incident_closeNotes = Option(
        doc="""**Syntax:** **incident_closeNotes=<string>** **Description:** Notes for closing the incident.""",
        require=False,
        default=None,
        validate=validators.Match("incident_closeNotes", r"^.*$"),
    )
    incident_closeReason = Option(
        doc="""**Syntax:** **incident_closeReason=<string>** **Description:** Reason for closing the incident.""",
        require=False,
        default=None,
        validate=validators.Match("incident_closeReason", r"^.*$"),
    )
    incident_closed = Option(
        doc="""**Syntax:** **incident_closed=<string>** **Description:** The date the incident was closed.""",
        require=False,
        default=None,
        validate=validators.Match("incident_closed", r"^.*$"),
    )
    incident_createInvestigation = Option(
        doc="""**Syntax:** **incident_createInvestigation=<bool>** **Description:** Whether to create an investigation for the incident.""",
        require=False,
        default=None,
        validate=validators.Boolean(),
    )
    incident_customFields = Option(
        doc="""**Syntax:** **incident_customFields=<string>** **Description:** Custom fields for the incident, as a JSON string.""",
        require=False,
        default=None,
        validate=validators.Match("incident_customFields", r"^.*$"),
    )
    incident_details = Option(
        doc="""**Syntax:** **incident_details=<string>** **Description:** The details of the incident.""",
        require=False,
        default=None,
        validate=validators.Match("incident_details", r"^.*$"),
    )
    incident_labels = Option(
        doc="""**Syntax:** **incident_labels=<string>** **Description:** Labels for the incident, as a JSON string.""",
        require=False,
        default=None,
        validate=validators.Match("incident_labels", r"^.*$"),
    )
    incident_modified = Option(
        doc="""**Syntax:** **incident_modified=<string>** **Description:** The date the incident was last modified.""",
        require=False,
        default=None,
        validate=validators.Match("incident_modified", r"^.*$"),
    )
    incident_name = Option(
        doc="""**Syntax:** **incident_name=<string>** **Description:** The name of the incident.""",
        require=False,
        default=None,
        validate=validators.Match("incident_name", r"^.*$"),
    )
    incident_playbookId = Option(
        doc="""**Syntax:** **incident_playbookId=<string>** **Description:** The ID of the playbook to run for the incident.""",
        require=False,
        default=None,
        validate=validators.Match("incident_playbookId", r"^.*$"),
    )
    incident_rawJSON = Option(
        doc="""**Syntax:** **incident_rawJSON=<string>** **Description:** The raw JSON of the incident.""",
        require=False,
        default=None,
        validate=validators.Match("incident_rawJSON", r"^.*$"),
    )
    incident_reason = Option(
        doc="""**Syntax:** **incident_reason=<string>** **Description:** The reason for the incident.""",
        require=False,
        default=None,
        validate=validators.Match("incident_reason", r"^.*$"),
    )
    incident_severity = Option(
        doc="""**Syntax:** **incident_severity=<number>** **Description:** The severity of the incident.""",
        require=False,
        default=None,
        validate=validators.Float(),
    )
    incident_sla = Option(
        doc="""**Syntax:** **incident_sla=<number>** **Description:** The SLA for the incident.""",
        require=False,
        default=None,
        validate=validators.Float(),
    )
    incident_status = Option(
        doc="""**Syntax:** **incident_status=<number>** **Description:** The status of the incident.""",
        require=False,
        default=None,
        validate=validators.Float(),
    )
    incident_type = Option(
        doc="""**Syntax:** **incident_type=<string>** **Description:** The type of the incident.""",
        require=False,
        default=None,
        validate=validators.Match("incident_type", r"^.*$"),
    )

    def stream(self, records):
        start = time.time()

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

        # get proxy_dict
        proxy_dict = reqinfo["ta_trackme_xsoar_conf"].get("proxy_dict", {})

        # init headers
        headers = {}

        # get the enable_resilient_store
        enable_resilient_store = int(
            reqinfo["ta_trackme_xsoar_conf"]["resilient_store"][
                "enable_resilient_store"
            ]
        )
        # turn int to a boolean
        enable_resilient_store = bool(enable_resilient_store)

        # earliest & latest
        earliest = self._metadata.searchinfo.earliest_time
        latest = self._metadata.searchinfo.latest_time

        # connect to the resilient store
        collection_name = "kv_xsoar_resilient_store"
        collection = self.service.kvstore[collection_name]

        # get the account information
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

        # generate the xsoar headers
        xsoar_headers = generate_xsoar_auth_headers(api_key_id, api_key_secret)
        headers.update(xsoar_headers)

        # get the xsoar url
        xsoar_url = account_info.get("xsoar_url")

        # ssl verification
        xsoar_ssl_verify = int(account_info.get("xsoar_ssl_verify", 1))

        if xsoar_ssl_verify == 0:
            verify_ssl = False
        else:
            verify_ssl = True

        # add content type
        headers["Content-Type"] = "application/json"

        # process records
        for record in records:

            # init the incident_json
            incident_json = {}

            # build the incident json from the command options with token replacement
            if self.incident_closeNotes:
                resolved_value = get_token_value(self.incident_closeNotes, record)
                if resolved_value:
                    incident_json["closeNotes"] = resolved_value
            if self.incident_closeReason:
                resolved_value = get_token_value(self.incident_closeReason, record)
                if resolved_value:
                    incident_json["closeReason"] = resolved_value
            if self.incident_closed:
                resolved_value = get_token_value(self.incident_closed, record)
                if resolved_value:
                    incident_json["closed"] = resolved_value
            if self.incident_createInvestigation is not None:
                # For boolean values, we need to handle token replacement differently
                if isinstance(self.incident_createInvestigation, str):
                    resolved_value = get_token_value(
                        self.incident_createInvestigation, record
                    )
                    if resolved_value:
                        # Convert string to boolean
                        incident_json["createInvestigation"] = (
                            resolved_value.lower() in ("true", "1", "yes", "on")
                        )
                else:
                    incident_json["createInvestigation"] = (
                        self.incident_createInvestigation
                    )
            if self.incident_customFields:
                resolved_value = get_token_value(self.incident_customFields, record)
                if resolved_value:
                    try:
                        incident_json["customFields"] = json.loads(resolved_value)
                    except Exception as e:
                        logging.error(
                            f'Error decoding customFields, value="{resolved_value}", error="{e}", skipping field.'
                        )
            if self.incident_details:
                resolved_value = get_token_value(self.incident_details, record)
                if resolved_value:
                    incident_json["details"] = resolved_value
            if self.incident_labels:
                resolved_value = get_token_value(self.incident_labels, record)
                if resolved_value:
                    try:
                        incident_json["labels"] = json.loads(resolved_value)
                    except Exception as e:
                        logging.error(
                            f'Error decoding labels, value="{resolved_value}", error="{e}", skipping field.'
                        )
            if self.incident_modified:
                resolved_value = get_token_value(self.incident_modified, record)
                if resolved_value:
                    incident_json["modified"] = resolved_value
            if self.incident_name:
                resolved_value = get_token_value(self.incident_name, record)
                if resolved_value:
                    incident_json["name"] = resolved_value
            if self.incident_playbookId:
                resolved_value = get_token_value(self.incident_playbookId, record)
                if resolved_value:
                    incident_json["playbookId"] = resolved_value
            if self.incident_rawJSON:
                resolved_value = get_token_value(self.incident_rawJSON, record)
                if resolved_value:
                    incident_json["rawJSON"] = resolved_value
            if self.incident_reason:
                resolved_value = get_token_value(self.incident_reason, record)
                if resolved_value:
                    incident_json["reason"] = resolved_value
            if self.incident_severity is not None:
                # For numeric values, handle token replacement
                if isinstance(self.incident_severity, str):
                    resolved_value = get_token_value(self.incident_severity, record)
                    if resolved_value:
                        try:
                            incident_json["severity"] = float(resolved_value)
                        except ValueError:
                            logging.error(
                                f'Error converting severity to float, value="{resolved_value}", skipping field.'
                            )
                else:
                    incident_json["severity"] = self.incident_severity
            if self.incident_sla is not None:
                # For numeric values, handle token replacement
                if isinstance(self.incident_sla, str):
                    resolved_value = get_token_value(self.incident_sla, record)
                    if resolved_value:
                        try:
                            incident_json["sla"] = float(resolved_value)
                        except ValueError:
                            logging.error(
                                f'Error converting sla to float, value="{resolved_value}", skipping field.'
                            )
                else:
                    incident_json["sla"] = self.incident_sla
            if self.incident_status is not None:
                # For numeric values, handle token replacement
                if isinstance(self.incident_status, str):
                    resolved_value = get_token_value(self.incident_status, record)
                    if resolved_value:
                        try:
                            incident_json["status"] = float(resolved_value)
                        except ValueError:
                            logging.error(
                                f'Error converting status to float, value="{resolved_value}", skipping field.'
                            )
                else:
                    incident_json["status"] = self.incident_status
            if self.incident_type:
                resolved_value = get_token_value(self.incident_type, record)
                if resolved_value:
                    incident_json["type"] = resolved_value

            # make the API call if there is content to send
            if incident_json:
                try:
                    response = requests.post(
                        f"{xsoar_url}/incident",
                        headers=headers,
                        data=json.dumps(incident_json),
                        verify=verify_ssl,
                        proxies=proxy_dict,
                    )

                    result_record = record.copy()
                    result_record["xsoar_status_code"] = response.status_code

                    if response.ok:
                        try:
                            result_record["xsoar_response"] = json.dumps(
                                response.json()
                            )
                            logging.debug(
                                f"xsoar_response={json.dumps(response.json())}"
                            )
                        except json.JSONDecodeError:
                            result_record["xsoar_response"] = response.text
                            logging.debug(f"xsoar_response={response.text}")
                    else:
                        result_record["xsoar_error"] = response.text
                        # store the record in the resilient store
                        if enable_resilient_store:
                            transaction_id = store_in_resilient_store(
                                self,
                                collection_name,
                                collection,
                                "incident",
                                "POST",
                                incident_json,
                                response.text,
                            )
                            result_record["message"] = (
                                f'record stored in the resilient store, transaction_id="{transaction_id}"'
                            )

                    yield result_record

                except Exception as e:
                    logging.error(f"Error calling XSOAR incident API: {e}")
                    error_record = record.copy()
                    error_record["error_message"] = str(e)

                    # store the record in the resilient store
                    if enable_resilient_store:
                        transaction_id = store_in_resilient_store(
                            self,
                            collection_name,
                            collection,
                            "incident",
                            "POST",
                            incident_json,
                            f"Error calling XSOAR incident API: {e}",
                        )
                        error_record["message"] = (
                            f'record stored in the resilient store, transaction_id="{transaction_id}"'
                        )
                    yield error_record

            else:
                # yield the record if no options were provided
                yield record

        # Log the run time
        logging.info(
            f"xsoar API command has terminated, response is logged in debug mode only, run_time={round(time.time() - start, 3)}"
        )


dispatch(xsoarRestHandler, sys.argv, sys.stdin, sys.stdout, __name__)
