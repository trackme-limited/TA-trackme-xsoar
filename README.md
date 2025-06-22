# TA-trackme-xsoar: Cortex XSOAR integration for TrackMe

## Introduction

**This integration provides REST API integration capabilities with Palo Alto Cortex XSOAR:**

- Create one or more XSOAR accounts in the application to interact on-demand with Cortex XSOAR.
- Authentication is based on XSOAR key and key ID as per the XSOAR API.
- Use the generating command ``xsoar`` to run GET/POST/DELETE REST calls to the XSOAR API.
- Use the streaming command ``xsoarstreamincident`` to create or update incidents in a streaming manner.
- Provides a resilient backend which automatically stores and reattempts failing REST API calls, for the purpose of incident management.
- Consistent and easy access to the different logs.

**Consult the Cortex SOAR REST API documentation:**

- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR-8-API

## Installation

**Install the application as usual in Splunk:**

- There are no dependencies.
- The application is developed on top of the Splunk UCC framework, and is compatible with all supported versions of Splunk.
- The application is compatible with both standalone instances and Search Head Cluster (SHC) deployments.
- The application is FIPS compatible.
- Ensure to restart Splunk after the initial installation on a standalone Splunk instance.

## Configuration

**After the installation, configure one or more Cortex XSOAR accounts:**

- Open the application, you automatically land in the Configuration screen.
- Click on Add to create a new Cortex XSOAR account
- In Cortex XSOAR, create a new API key (see: https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR-8-API/Create-a-new-API-key), note the key value and the key ID.
- In Splunk, define a name for this account (e.g., xsoar), insert the key and key ID, configure other options as needed.

**About RBAC:**

- The application leverages RBAC and granular privilege escalation.
- However, note that the Configuration screen requires admin privileges.
- To be granted the right to use the application, a user must be a member of the listed roles in the Role-Based Access Control section.
- Also, the application leverages a custom capability called ``xsoarapi``, if you add your own role and the role is not inheriting from admin or sc_admin, **you must add this capability or the application will refuse access**.

**Testing the connectivity:**

To test the connectivity, you can simply run any GET call against the XSOAR REST API using the ``xsoar`` command, for instance:

    | xsoar account=xsoar url="incidentfields" mode=get

If the connection or the command fails for any reason, networking or authentication issues, an exception will be raised and the reason provided.

*You can also consult the logs of the command:*

    index=_internal sourcetype=xsoar:custom_commands:xsoar log_level=error

## Using the command xsoar

*The command xsoar can be used for GET/POST/DELETE calls, such as:*

    | xsoar account=xsoar url="incidentfields" mode=post body="{\"details\": \"My test incident\", \"name\": \"My test incident\", \"severity\": 2, \"type\": \"unclassified\"}"

*See:*

- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR-8-API/Make-your-first-API-call

## Creating and updating incidents using the command xsoarstreamincident

The command xsoarstreamincident is designed to create and update incidents in a streaming manner, and can be called as:

    | makeresults
    | xsoarstreamincident account="xsoar" incident_details="My test incident" incident_name="My test incident" incident_severity=2 incident_type="unclassified"

The following arguments are made available within the command, as arguments, which correspond to the endpoint body parameters:

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

*See:*

- https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR-8-API/Create-or-update-an-incident

*Logs are available in:*

    index=_internal sourcetype=xsoar:custom_commands:xsoarstreamincident

## About the resilient store

The application will store failing calls in a Splunk KVstore, for automated reattempt purposes:

- KVstore name: kv_xsoar_resilient_store
- KVstore transforms name: xsoar_resilient_store

*You can access the KVstore content using the Splunk search:*

    | inputlookup xsoar_resilient_store | eval keyid=_key

The resilient store behaviors can be configured in the **Resilient Store** configuration section:

- You can choose to enable or disable entirely the resilient store functionalities. (default is enabled)
- You can define the maximum number of attempts for a given REST call represented by a transaction ID. (which also defines the KVstore unique key ID)

The resilient store processes automated reattempts using the command ``xsoarresilient`` and is orchestrated by the saved search named: (scheduled is enabled by default)

- xsoarresilient

Behaviors:

- When a reattempt is needed and processed successfully, the information is logged and the KVstore record is permanently deleted.
- When a transaction ID record reaches the maximum number of attempts, the information is logged and the KVstore record is permanently deleted.

*You can review the resilient store logs in:*

    index=_internal sourcetype=xsoar:custom_commands:xsoarresilient

## Troubleshoot

The application provides a menu "Audit && Troubleshoot" with shortcuts to the internal log events, you can use the extracted field ``log_level`` to filter on a certain type of log events such as ``error``.

### Application internal REST API

    index=_internal sourcetype=xsoar:rest_api

### Command xsoar

    index=_internal sourcetype=xsoar:custom_commands:xsoar

### Command xsoarstreamincident

    index=_internal sourcetype=xsoar:custom_commands:xsoarstreamincident

### Command xsoarresilient

    index=_internal sourcetype=xsoar:custom_commands:xsoarresilient
