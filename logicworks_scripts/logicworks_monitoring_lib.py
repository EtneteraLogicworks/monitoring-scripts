#!/usr/bin/env python3
"""logicworks_monitoring_lib
Library with common code for other Logicworks monitoring scripts
"""

import argparse
import re
import sys

from pysnmp.hlapi import (ContextData, SnmpEngine, UdpTransportTarget,
                          UsmUserData, getCmd, usmAesCfb128Protocol,
                          usmDESPrivProtocol, usmHMACMD5AuthProtocol,
                          usmHMACSHAAuthProtocol)

SNMP_PORT = 161
DEFAULT_PRIV_PROTOCOL = "DES"
DEFAULT_AUTH_PROTOCOL = "SHA"


def add_common_snmp_args(parser):
    """Initialize common args for SNMPv3"""
    parser.add_argument(
        "-H", "--host", required=True, help="Name or IPv4 address of host to check"
    )
    parser.add_argument(
        "-P", "--port", default=SNMP_PORT, help=f"SNMP port (Default {SNMP_PORT})"
    )
    parser.add_argument(
        "-u", "--user", required=True, help="User for snmpv3 authentication "
    )
    parser.add_argument(
        "-a",
        "--authprotocol",
        default=DEFAULT_AUTH_PROTOCOL,
        help="Auth protocol for snmpv3",
    )
    parser.add_argument(
        "-A", "--authpassword", help="Password for snmpv3 authentication ",
    )
    parser.add_argument(
        "-X", "--privpassword", required=True, help="Password for snmpv3 privacy ",
    )
    parser.add_argument(
        "-x",
        "--privprotocol",
        default=DEFAULT_PRIV_PROTOCOL,
        help="Privacy protocol for snmpv3",
    )


def add_response_to_dataset(dataset, varBinds, item_description):
    """Parse single SNMP response"""
    for varBind in varBinds:
        var, value = [x.prettyPrint() for x in varBind]
        match_key = re.search(f"({item_description}.*)[.]", var)
        if match_key:
            dataset[match_key.group(1)] = value


def get_snmp_data(config, data):
    """Retrieve necessary data via SNMP"""

    if config["privprotocol"] == "AES":
        priv_protocol = usmAesCfb128Protocol
    elif config["privprotocol"] == "DES":
        priv_protocol = usmDESPrivProtocol
    else:
        raise ValueError(f"Unknown privprotocol {config['privprotocol']}")

    if config["authprotocol"] == "SHA":
        auth_protocol = usmHMACSHAAuthProtocol
    elif config["authprotocol"] == "MD5":
        auth_protocol = usmHMACMD5AuthProtocol
    else:
        raise ValueError(f"Unknown authprotocol {config['authprotocol']}")

    authdata = UsmUserData(
        config["user"],
        authKey=config["authpassword"],
        privKey=config["privpassword"],
        authProtocol=auth_protocol,
        privProtocol=priv_protocol,
    )
    target = UdpTransportTarget((config["host"], config["port"]))

    errorIndication, errorStatus, errorIndex, varBinds = next(
        getCmd(SnmpEngine(), authdata, target, ContextData(), data)
    )
    if errorIndication:
        raise ValueError(errorIndication)
    elif errorStatus:
        status = errorStatus.prettyPrint()
        index = errorIndex and varBinds[int(errorIndex) - 1][0] or "?"
        raise ValueError(f"{status} at {index}")

    return varBinds


def unknown_exit(service, message):
    """Exit in unknown state when"""
    print(f"{service} UNKNOWN - {message}")
    sys.exit(3)


def report(state, message):
    """Print message string and exit"""
    print(message)
    if state == "OK":
        sys.exit(0)
    elif state == "WARNING":
        sys.exit(1)
    elif state == "CRITICAL":
        sys.exit(2)
    elif state == "UNKNOWN":
        sys.exit(3)
