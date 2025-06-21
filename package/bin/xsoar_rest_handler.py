from __future__ import absolute_import, division, print_function, unicode_literals

__name__ = "xsoar_rest_handler.py"
__author__ = "TrackMe Limited"
__copyright__ = "Copyright 2021-2025, TrackMe Limited, U.K."
__credits__ = "TrackMe Limited, U.K."
__license__ = "TrackMe Limited, all rights reserved"
__version__ = "0.1.0"
__maintainer__ = "TrackMe Limited, U.K."
__email__ = "support@trackme-solutions.com"
__status__ = "PRODUCTION"

# Standard library imports
import json
import logging
import os
import sys
import time
from urllib.parse import urlencode
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# append lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-trackme-xsoar", "lib"))

# set logging
from xsoar_libs_logging import setup_logger

logger = setup_logger("trackme.rest.xsoar", "trackme_rest_api_xsoar.log")

# import API handler
import rest_handler

# import Splunk libs
import splunklib.client as client
import splunklib.results as results

# import xsoar libs
from xsoar_libs import (
    xsoar_getloglevel,
    xsoar_get_account,
)


class XsoarApi_v1(rest_handler.RESTHandler):
    def __init__(self, command_line, command_arg):
        super(XsoarApi_v1, self).__init__(command_line, command_arg, logger)

    # Return request info
    def get_request_info(self, request_info, **kwargs):
        describe = False

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        if resp_dict is not None:
            try:
                describe = resp_dict["describe"]
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
        else:
            # body is not required in this endpoint, if not submitted do not describe the usage
            describe = False

        # if describe is requested, show the usage
        if describe:
            response = {
                "describe": "This endpoint returns the request info such as splunkd_uri and other useful technical information, it requires a GET call with no options",
                "resource_desc": "Return reqinfo",
                "resource_spl_example": '| xsoar mode=get url="/services/xsoar/v1/request_info"',
            }

            return {"payload": response, "status": 200}

        # Get splunkd port
        splunkd_port = request_info.server_rest_port

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-trackme-xsoar",
            port=splunkd_port,
            token=request_info.system_authtoken,
        )

        # set loglevel
        loglevel = xsoar_getloglevel(
            request_info.system_authtoken, request_info.server_rest_port
        )
        logger.setLevel(loglevel)

        # conf
        conf_file = "ta_trackme_xsoar_settings"
        confs = service.confs[str(conf_file)]

        # Initialize the trackme_conf dictionary
        ta_trackme_xsoar_conf = {}

        # Get conf
        for stanza in confs:
            logger.debug(f'get_trackme_conf, Processing stanza.name="{stanza.name}"')
            # Create a sub-dictionary for the current stanza name if it doesn't exist
            if stanza.name not in ta_trackme_xsoar_conf:
                ta_trackme_xsoar_conf[stanza.name] = {}

            # Store key-value pairs from the stanza content in the corresponding sub-dictionary
            for stanzakey, stanzavalue in stanza.content.items():
                logger.debug(
                    f'ta_trackme_xsoar_conf, Processing stanzakey="{stanzakey}", stanzavalue="{stanzavalue}"'
                )
                ta_trackme_xsoar_conf[stanza.name][stanzakey] = stanzavalue

        # gen record
        record = {
            "user": request_info.user,
            "server_rest_uri": request_info.server_rest_uri,
            "server_rest_host": request_info.server_rest_host,
            "server_rest_port": request_info.server_rest_port,
            "server_hostname": request_info.server_hostname,
            "server_servername": request_info.server_servername,
            "connection_src_ip": request_info.connection_src_ip,
            "connection_listening_port": request_info.connection_listening_port,
            "logging_level": ta_trackme_xsoar_conf["logging"]["loglevel"],
            "ta_trackme_xsoar_conf": ta_trackme_xsoar_conf,
        }

        logger.info(f"get_request_info, record={record}")

        return {"payload": record, "status": 200}

    # Get account credentials with a least privileges approach
    def post_get_account(self, request_info, **kwargs):
        describe = False
        logger.info(f"Starting post_get_account, request_info={request_info}")

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        logger.info(f"resp_dict is {resp_dict}")

        if resp_dict is not None:
            try:
                describe = resp_dict["describe"]
                if describe in ("true", "True"):
                    describe = True
            except Exception as e:
                describe = False
                account = resp_dict["account"]
        else:
            # body is not required in this endpoint, if not submitted do not describe the usage
            describe = False

        # if describe is requested, show the usage
        if describe:
            response = {
                "describe": "This endpoint provides connection details for a Splunk remote account to be used in a programmatic manner with a least privileges approach, it requires a POST call with the following options:",
                "resource_desc": "Return a remote account credential details for programmatic access with a least privileges approach",
                "resource_spl_example": "| xsoar mode=post url=\"/services/xsoar/v1/get_account\" body=\"{'account': 'xsoar'}\"",
                "options": [
                    {
                        "account": "The account configuration identifier",
                    }
                ],
            }
            return {"payload": response, "status": 200}

        # Get splunkd port
        splunkd_port = request_info.server_rest_port

        # Get service
        service = client.connect(
            owner="nobody",
            app="TA-trackme-xsoar",
            port=splunkd_port,
            token=request_info.system_authtoken,
        )

        # set loglevel
        loglevel = xsoar_getloglevel(
            request_info.system_authtoken, request_info.server_rest_port
        )
        logger.setLevel(loglevel)

        # get all acounts
        try:
            accounts = []
            conf_file = "ta_trackme_xsoar_settings"
            confs = service.confs[str(conf_file)]
            for stanza in confs:
                # get all accounts
                for name in stanza.name:
                    accounts.append(stanza.name)
                    break

        except Exception as e:
            error_msg = "There are no remote Splunk account configured yet"
            return {
                "payload": {
                    "status": "failure",
                    "message": error_msg,
                    "account": account,
                },
                "status": 500,
            }

        else:
            try:
                response = xsoar_get_account(request_info, account)
                return {"payload": response, "status": 200}

            # note: the exception is returned as a JSON object
            except Exception as e:
                return {"payload": str(e), "status": 500}
