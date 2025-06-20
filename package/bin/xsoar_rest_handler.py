from __future__ import absolute_import, division, print_function, unicode_literals

__name__ = "xsoar_rest_handler.py"
__author__ = "TrackMe Limited U.K"

# Standard library imports
import json
import logging
import os
import sys
import time
from urllib.parse import urlencode
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Third-party library imports
from logging.handlers import RotatingFileHandler

# splunk home
splunkhome = os.environ["SPLUNK_HOME"]

# set logging
logger = logging.getLogger(__name__)
filehandler = RotatingFileHandler(
    "%s/var/log/splunk/ta_trackme_xsoar_rest_api.log" % splunkhome,
    mode="a",
    maxBytes=10000000,
    backupCount=1,
)
formatter = logging.Formatter(
    "%(asctime)s %(levelname)s %(filename)s %(funcName)s %(lineno)d %(message)s"
)
logging.Formatter.converter = time.gmtime
filehandler.setFormatter(formatter)
log = logging.getLogger()
for hdlr in log.handlers[:]:
    if isinstance(hdlr, logging.FileHandler):
        log.removeHandler(hdlr)
log.addHandler(filehandler)
log.setLevel(logging.INFO)

# append lib
sys.path.append(os.path.join(splunkhome, "etc", "apps", "TA-trackme-xsoar", "lib"))

# import API handler
import rest_handler

# import Splunk libs
import splunklib.client as client
import splunklib.results as results

# import xsoar libs
from xsoar_libs import (
    xsoar_getloglevel,
    xsoar_test_remote_connectivity,
    xsoar_get_account,
)


class xsoarApi_v1(rest_handler.RESTHandler):
    def __init__(self, command_line, command_arg):
        super(xsoarApi_v1, self).__init__(command_line, command_arg, logger)

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

        # conf
        conf_file = "ta_trackme_xsoar_settings"
        confs = service.confs[str(conf_file)]

        # Initialize the trackme_conf dictionary
        ta_trackme_xsoar_conf = {}

        # Get conf
        for stanza in confs:
            logging.debug(f'get_trackme_conf, Processing stanza.name="{stanza.name}"')
            # Create a sub-dictionary for the current stanza name if it doesn't exist
            if stanza.name not in ta_trackme_xsoar_conf:
                ta_trackme_xsoar_conf[stanza.name] = {}

            # Store key-value pairs from the stanza content in the corresponding sub-dictionary
            for stanzakey, stanzavalue in stanza.content.items():
                logging.debug(
                    f'ta_trackme_xsoar_conf, Processing stanzakey="{stanzakey}", stanzavalue="{stanzavalue}"'
                )
                ta_trackme_xsoar_conf[stanza.name][stanzakey] = stanzavalue

        # set logging_level
        logginglevel = logging.getLevelName(
            ta_trackme_xsoar_conf["logging"]["loglevel"]
        )
        log.setLevel(logginglevel)

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

        return {"payload": record, "status": 200}

    # Test xsoar connectivity prior to the creation of a xsoar account
    def post_test_xsoar_connectivity(self, request_info, **kwargs):
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
                xsoar_deployment_type = resp_dict.get("xsoar_deployment_type", "cloud")
                xsoar_cloud_organization_id = resp_dict.get(
                    "xsoar_cloud_organization_id", None
                )
                xsoar_onprem_leader_url = resp_dict.get("xsoar_onprem_leader_url", None)
                xsoar_client_id = resp_dict.get("xsoar_client_id", None)
                xsoar_client_secret = resp_dict.get("xsoar_client_secret", None)
                xsoar_ssl_verify = resp_dict.get("xsoar_ssl_verify", 1)
                xsoar_ssl_certificate_path = resp_dict.get(
                    "xsoar_ssl_certificate_path", None
                )
        else:
            # body is not required in this endpoint, if not submitted do not describe the usage
            describe = False

        # if describe is requested, show the usage
        if describe:
            response = {
                "describe": "This endpoint performs a connectivity check for xsoar API prior to the configuration of the account, it requires a POST call with the following options:",
                "resource_desc": "Run connectivity checks for xsoar API prior to the creation fo an account, this validates the configuration, network connectivity and authentication",
                "resource_spl_example": "| xsoar mode=post url=\"/services/xsoar/v1/test_xsoar_connectivity\" body=\"{'xsoar_deployment_type': 'cloud', 'xsoar_client_id': '<client_id>', 'xsoar_api_password': '<xsoar_client_secret>'}\"",
                "options": [
                    {
                        "xsoar_deployment_type": "The xsoar deployment type, valid options: cloud | onprem",
                        "xsoar_onprem_leader_url": "For on-premise, The xsoar leader url in the form: https://<url>:<port>",
                        "xsoar_client_id": "The usernane if using on-premise, client_id if using Cloud",
                        "xsoar_client_secret": "The password if using on-premise, client_secret if using Cloud",
                        "xsoar_ssl_verify": "For on-prem only, enable or disable the SSL certificate validation",
                        "xsoar_ssl_certificate_path": "For on-prem only, specify the path on the file-system to the certificate file for SSL validation",
                    }
                ],
            }
            return {"payload": response, "status": 200}

        # set loglevel
        loglevel = xsoar_getloglevel(
            request_info.system_authtoken, request_info.server_rest_port
        )
        log.setLevel(logging.getLevelName(loglevel))

        try:
            connection_info = {
                "xsoar_deployment_type": xsoar_deployment_type,
                "xsoar_cloud_organization_id": xsoar_cloud_organization_id,
                "xsoar_onprem_leader_url": xsoar_onprem_leader_url,
                "xsoar_client_id": xsoar_client_id,
                "xsoar_client_secret": xsoar_client_secret,
                "xsoar_ssl_verify": xsoar_ssl_verify,
                "xsoar_ssl_certificate_path": xsoar_ssl_certificate_path,
            }
            response = xsoar_test_remote_connectivity(connection_info)
            return {"payload": response, "status": 200}

        # note: the exception is returned as a JSON object
        except Exception as e:
            return {"payload": str(e), "status": 500}

    # Get account credentials with a least privileges approach
    def post_get_account(self, request_info, **kwargs):
        describe = False
        logging.info(f"Starting post_get_account, request_info={request_info}")

        # Retrieve from data
        try:
            resp_dict = json.loads(str(request_info.raw_args["payload"]))
        except Exception as e:
            resp_dict = None

        logging.info(f"resp_dict is {resp_dict}")

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
        log.setLevel(logging.getLevelName(loglevel))

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
