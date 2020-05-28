#
# PySNMP MIB module BRIDGE-MIB (http://snmplabs.com/pysmi)
# ASN.1 source file:///usr/share/snmp/mibs/ietf/BRIDGE-MIB
# Produced by pysmi-0.3.2 at Tue Apr  7 17:35:33 2020
# On host sensei platform Linux version 4.19.97-v7l+ by user nagios
# Using Python version 3.7.3 (default, Dec 20 2019, 18:57:59) 
#
OctetString, Integer, ObjectIdentifier = mibBuilder.importSymbols("ASN1", "OctetString", "Integer", "ObjectIdentifier")
NamedValues, = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
ValueSizeConstraint, ConstraintsUnion, ValueRangeConstraint, SingleValueConstraint, ConstraintsIntersection = mibBuilder.importSymbols("ASN1-REFINEMENT", "ValueSizeConstraint", "ConstraintsUnion", "ValueRangeConstraint", "SingleValueConstraint", "ConstraintsIntersection")
InterfaceIndex, = mibBuilder.importSymbols("IF-MIB", "InterfaceIndex")
NotificationGroup, ObjectGroup, ModuleCompliance = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ObjectGroup", "ModuleCompliance")
Counter64, IpAddress, TimeTicks, MibIdentifier, Gauge32, MibScalar, MibTable, MibTableRow, MibTableColumn, Counter32, NotificationType, ObjectIdentity, mib_2, ModuleIdentity, Unsigned32, Integer32, Bits, iso = mibBuilder.importSymbols("SNMPv2-SMI", "Counter64", "IpAddress", "TimeTicks", "MibIdentifier", "Gauge32", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "Counter32", "NotificationType", "ObjectIdentity", "mib-2", "ModuleIdentity", "Unsigned32", "Integer32", "Bits", "iso")
TextualConvention, DisplayString, MacAddress = mibBuilder.importSymbols("SNMPv2-TC", "TextualConvention", "DisplayString", "MacAddress")
dot1dBridge = ModuleIdentity((1, 3, 6, 1, 2, 1, 17))
dot1dBridge.setRevisions(('2005-09-19 00:00', '1993-07-31 00:00', '1991-12-31 00:00',))
if mibBuilder.loadTexts: dot1dBridge.setLastUpdated('200509190000Z')
if mibBuilder.loadTexts: dot1dBridge.setOrganization('IETF Bridge MIB Working Group')
class BridgeId(TextualConvention, OctetString):
    status = 'current'
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(8, 8)
    fixedLength = 8

class Timeout(TextualConvention, Integer32):
    status = 'current'
    displayHint = 'd'

dot1dNotifications = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 0))
dot1dBase = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 1))
dot1dStp = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 2))
dot1dSr = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 3))
dot1dTp = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 4))
dot1dStatic = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 5))
dot1dConformance = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 8))
dot1dBaseBridgeAddress = MibScalar((1, 3, 6, 1, 2, 1, 17, 1, 1), MacAddress()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dBaseBridgeAddress.setStatus('current')
dot1dBaseNumPorts = MibScalar((1, 3, 6, 1, 2, 1, 17, 1, 2), Integer32()).setUnits('ports').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dBaseNumPorts.setStatus('current')
dot1dBaseType = MibScalar((1, 3, 6, 1, 2, 1, 17, 1, 3), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3, 4))).clone(namedValues=NamedValues(("unknown", 1), ("transparent-only", 2), ("sourceroute-only", 3), ("srt", 4)))).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dBaseType.setStatus('current')
dot1dBasePortTable = MibTable((1, 3, 6, 1, 2, 1, 17, 1, 4), )
if mibBuilder.loadTexts: dot1dBasePortTable.setStatus('current')
dot1dBasePortEntry = MibTableRow((1, 3, 6, 1, 2, 1, 17, 1, 4, 1), ).setIndexNames((0, "BRIDGE-MIB", "dot1dBasePort"))
if mibBuilder.loadTexts: dot1dBasePortEntry.setStatus('current')
dot1dBasePort = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 1), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1, 65535))).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dBasePort.setStatus('current')
dot1dBasePortIfIndex = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2), InterfaceIndex()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dBasePortIfIndex.setStatus('current')
dot1dBasePortCircuit = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 3), ObjectIdentifier()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dBasePortCircuit.setStatus('current')
dot1dBasePortDelayExceededDiscards = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 4), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dBasePortDelayExceededDiscards.setStatus('current')
dot1dBasePortMtuExceededDiscards = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 5), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dBasePortMtuExceededDiscards.setStatus('current')
dot1dStpProtocolSpecification = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 1), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3))).clone(namedValues=NamedValues(("unknown", 1), ("decLb100", 2), ("ieee8021d", 3)))).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpProtocolSpecification.setStatus('current')
dot1dStpPriority = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 2), Integer32().subtype(subtypeSpec=ValueRangeConstraint(0, 65535))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dStpPriority.setStatus('current')
dot1dStpTimeSinceTopologyChange = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 3), TimeTicks()).setUnits('centi-seconds').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpTimeSinceTopologyChange.setStatus('current')
dot1dStpTopChanges = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 4), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpTopChanges.setStatus('current')
dot1dStpDesignatedRoot = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 5), BridgeId()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpDesignatedRoot.setStatus('current')
dot1dStpRootCost = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 6), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpRootCost.setStatus('current')
dot1dStpRootPort = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 7), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpRootPort.setStatus('current')
dot1dStpMaxAge = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 8), Timeout()).setUnits('centi-seconds').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpMaxAge.setStatus('current')
dot1dStpHelloTime = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 9), Timeout()).setUnits('centi-seconds').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpHelloTime.setStatus('current')
dot1dStpHoldTime = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 10), Integer32()).setUnits('centi-seconds').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpHoldTime.setStatus('current')
dot1dStpForwardDelay = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 11), Timeout()).setUnits('centi-seconds').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpForwardDelay.setStatus('current')
dot1dStpBridgeMaxAge = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 12), Timeout().subtype(subtypeSpec=ValueRangeConstraint(600, 4000))).setUnits('centi-seconds').setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dStpBridgeMaxAge.setStatus('current')
dot1dStpBridgeHelloTime = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 13), Timeout().subtype(subtypeSpec=ValueRangeConstraint(100, 1000))).setUnits('centi-seconds').setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dStpBridgeHelloTime.setStatus('current')
dot1dStpBridgeForwardDelay = MibScalar((1, 3, 6, 1, 2, 1, 17, 2, 14), Timeout().subtype(subtypeSpec=ValueRangeConstraint(400, 3000))).setUnits('centi-seconds').setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dStpBridgeForwardDelay.setStatus('current')
dot1dStpPortTable = MibTable((1, 3, 6, 1, 2, 1, 17, 2, 15), )
if mibBuilder.loadTexts: dot1dStpPortTable.setStatus('current')
dot1dStpPortEntry = MibTableRow((1, 3, 6, 1, 2, 1, 17, 2, 15, 1), ).setIndexNames((0, "BRIDGE-MIB", "dot1dStpPort"))
if mibBuilder.loadTexts: dot1dStpPortEntry.setStatus('current')
dot1dStpPort = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 1), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1, 65535))).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpPort.setStatus('current')
dot1dStpPortPriority = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 2), Integer32().subtype(subtypeSpec=ValueRangeConstraint(0, 255))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dStpPortPriority.setStatus('current')
dot1dStpPortState = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 3), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3, 4, 5, 6))).clone(namedValues=NamedValues(("disabled", 1), ("blocking", 2), ("listening", 3), ("learning", 4), ("forwarding", 5), ("broken", 6)))).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpPortState.setStatus('current')
dot1dStpPortEnable = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 4), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2))).clone(namedValues=NamedValues(("enabled", 1), ("disabled", 2)))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dStpPortEnable.setStatus('current')
dot1dStpPortPathCost = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 5), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1, 65535))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dStpPortPathCost.setStatus('current')
dot1dStpPortDesignatedRoot = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 6), BridgeId()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpPortDesignatedRoot.setStatus('current')
dot1dStpPortDesignatedCost = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 7), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpPortDesignatedCost.setStatus('current')
dot1dStpPortDesignatedBridge = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 8), BridgeId()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpPortDesignatedBridge.setStatus('current')
dot1dStpPortDesignatedPort = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 9), OctetString().subtype(subtypeSpec=ValueSizeConstraint(2, 2)).setFixedLength(2)).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpPortDesignatedPort.setStatus('current')
dot1dStpPortForwardTransitions = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 10), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dStpPortForwardTransitions.setStatus('current')
dot1dStpPortPathCost32 = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 2, 15, 1, 11), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1, 200000000))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dStpPortPathCost32.setStatus('current')
dot1dTpLearnedEntryDiscards = MibScalar((1, 3, 6, 1, 2, 1, 17, 4, 1), Counter32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpLearnedEntryDiscards.setStatus('current')
dot1dTpAgingTime = MibScalar((1, 3, 6, 1, 2, 1, 17, 4, 2), Integer32().subtype(subtypeSpec=ValueRangeConstraint(10, 1000000))).setUnits('seconds').setMaxAccess("readwrite")
if mibBuilder.loadTexts: dot1dTpAgingTime.setStatus('current')
dot1dTpFdbTable = MibTable((1, 3, 6, 1, 2, 1, 17, 4, 3), )
if mibBuilder.loadTexts: dot1dTpFdbTable.setStatus('current')
dot1dTpFdbEntry = MibTableRow((1, 3, 6, 1, 2, 1, 17, 4, 3, 1), ).setIndexNames((0, "BRIDGE-MIB", "dot1dTpFdbAddress"))
if mibBuilder.loadTexts: dot1dTpFdbEntry.setStatus('current')
dot1dTpFdbAddress = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 1), MacAddress()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpFdbAddress.setStatus('current')
dot1dTpFdbPort = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2), Integer32()).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpFdbPort.setStatus('current')
dot1dTpFdbStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3, 4, 5))).clone(namedValues=NamedValues(("other", 1), ("invalid", 2), ("learned", 3), ("self", 4), ("mgmt", 5)))).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpFdbStatus.setStatus('current')
dot1dTpPortTable = MibTable((1, 3, 6, 1, 2, 1, 17, 4, 4), )
if mibBuilder.loadTexts: dot1dTpPortTable.setStatus('current')
dot1dTpPortEntry = MibTableRow((1, 3, 6, 1, 2, 1, 17, 4, 4, 1), ).setIndexNames((0, "BRIDGE-MIB", "dot1dTpPort"))
if mibBuilder.loadTexts: dot1dTpPortEntry.setStatus('current')
dot1dTpPort = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 4, 4, 1, 1), Integer32().subtype(subtypeSpec=ValueRangeConstraint(1, 65535))).setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpPort.setStatus('current')
dot1dTpPortMaxInfo = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 4, 4, 1, 2), Integer32()).setUnits('bytes').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpPortMaxInfo.setStatus('current')
dot1dTpPortInFrames = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 4, 4, 1, 3), Counter32()).setUnits('frames').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpPortInFrames.setStatus('current')
dot1dTpPortOutFrames = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 4, 4, 1, 4), Counter32()).setUnits('frames').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpPortOutFrames.setStatus('current')
dot1dTpPortInDiscards = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 4, 4, 1, 5), Counter32()).setUnits('frames').setMaxAccess("readonly")
if mibBuilder.loadTexts: dot1dTpPortInDiscards.setStatus('current')
dot1dStaticTable = MibTable((1, 3, 6, 1, 2, 1, 17, 5, 1), )
if mibBuilder.loadTexts: dot1dStaticTable.setStatus('current')
dot1dStaticEntry = MibTableRow((1, 3, 6, 1, 2, 1, 17, 5, 1, 1), ).setIndexNames((0, "BRIDGE-MIB", "dot1dStaticAddress"), (0, "BRIDGE-MIB", "dot1dStaticReceivePort"))
if mibBuilder.loadTexts: dot1dStaticEntry.setStatus('current')
dot1dStaticAddress = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 5, 1, 1, 1), MacAddress()).setMaxAccess("readcreate")
if mibBuilder.loadTexts: dot1dStaticAddress.setStatus('current')
dot1dStaticReceivePort = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 5, 1, 1, 2), Integer32().subtype(subtypeSpec=ValueRangeConstraint(0, 65535))).setMaxAccess("readcreate")
if mibBuilder.loadTexts: dot1dStaticReceivePort.setStatus('current')
dot1dStaticAllowedToGoTo = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 5, 1, 1, 3), OctetString().subtype(subtypeSpec=ValueSizeConstraint(0, 512))).setMaxAccess("readcreate")
if mibBuilder.loadTexts: dot1dStaticAllowedToGoTo.setStatus('current')
dot1dStaticStatus = MibTableColumn((1, 3, 6, 1, 2, 1, 17, 5, 1, 1, 4), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3, 4, 5))).clone(namedValues=NamedValues(("other", 1), ("invalid", 2), ("permanent", 3), ("deleteOnReset", 4), ("deleteOnTimeout", 5)))).setMaxAccess("readcreate")
if mibBuilder.loadTexts: dot1dStaticStatus.setStatus('current')
newRoot = NotificationType((1, 3, 6, 1, 2, 1, 17, 0, 1))
if mibBuilder.loadTexts: newRoot.setStatus('current')
topologyChange = NotificationType((1, 3, 6, 1, 2, 1, 17, 0, 2))
if mibBuilder.loadTexts: topologyChange.setStatus('current')
dot1dGroups = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 8, 1))
dot1dCompliances = MibIdentifier((1, 3, 6, 1, 2, 1, 17, 8, 2))
dot1dBaseBridgeGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 1)).setObjects(("BRIDGE-MIB", "dot1dBaseBridgeAddress"), ("BRIDGE-MIB", "dot1dBaseNumPorts"), ("BRIDGE-MIB", "dot1dBaseType"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dBaseBridgeGroup = dot1dBaseBridgeGroup.setStatus('current')
dot1dBasePortGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 2)).setObjects(("BRIDGE-MIB", "dot1dBasePort"), ("BRIDGE-MIB", "dot1dBasePortIfIndex"), ("BRIDGE-MIB", "dot1dBasePortCircuit"), ("BRIDGE-MIB", "dot1dBasePortDelayExceededDiscards"), ("BRIDGE-MIB", "dot1dBasePortMtuExceededDiscards"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dBasePortGroup = dot1dBasePortGroup.setStatus('current')
dot1dStpBridgeGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 3)).setObjects(("BRIDGE-MIB", "dot1dStpProtocolSpecification"), ("BRIDGE-MIB", "dot1dStpPriority"), ("BRIDGE-MIB", "dot1dStpTimeSinceTopologyChange"), ("BRIDGE-MIB", "dot1dStpTopChanges"), ("BRIDGE-MIB", "dot1dStpDesignatedRoot"), ("BRIDGE-MIB", "dot1dStpRootCost"), ("BRIDGE-MIB", "dot1dStpRootPort"), ("BRIDGE-MIB", "dot1dStpMaxAge"), ("BRIDGE-MIB", "dot1dStpHelloTime"), ("BRIDGE-MIB", "dot1dStpHoldTime"), ("BRIDGE-MIB", "dot1dStpForwardDelay"), ("BRIDGE-MIB", "dot1dStpBridgeMaxAge"), ("BRIDGE-MIB", "dot1dStpBridgeHelloTime"), ("BRIDGE-MIB", "dot1dStpBridgeForwardDelay"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dStpBridgeGroup = dot1dStpBridgeGroup.setStatus('current')
dot1dStpPortGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 4)).setObjects(("BRIDGE-MIB", "dot1dStpPort"), ("BRIDGE-MIB", "dot1dStpPortPriority"), ("BRIDGE-MIB", "dot1dStpPortState"), ("BRIDGE-MIB", "dot1dStpPortEnable"), ("BRIDGE-MIB", "dot1dStpPortPathCost"), ("BRIDGE-MIB", "dot1dStpPortDesignatedRoot"), ("BRIDGE-MIB", "dot1dStpPortDesignatedCost"), ("BRIDGE-MIB", "dot1dStpPortDesignatedBridge"), ("BRIDGE-MIB", "dot1dStpPortDesignatedPort"), ("BRIDGE-MIB", "dot1dStpPortForwardTransitions"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dStpPortGroup = dot1dStpPortGroup.setStatus('current')
dot1dStpPortGroup2 = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 5)).setObjects(("BRIDGE-MIB", "dot1dStpPort"), ("BRIDGE-MIB", "dot1dStpPortPriority"), ("BRIDGE-MIB", "dot1dStpPortState"), ("BRIDGE-MIB", "dot1dStpPortEnable"), ("BRIDGE-MIB", "dot1dStpPortDesignatedRoot"), ("BRIDGE-MIB", "dot1dStpPortDesignatedCost"), ("BRIDGE-MIB", "dot1dStpPortDesignatedBridge"), ("BRIDGE-MIB", "dot1dStpPortDesignatedPort"), ("BRIDGE-MIB", "dot1dStpPortForwardTransitions"), ("BRIDGE-MIB", "dot1dStpPortPathCost32"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dStpPortGroup2 = dot1dStpPortGroup2.setStatus('current')
dot1dStpPortGroup3 = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 6)).setObjects(("BRIDGE-MIB", "dot1dStpPortPathCost32"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dStpPortGroup3 = dot1dStpPortGroup3.setStatus('current')
dot1dTpBridgeGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 7)).setObjects(("BRIDGE-MIB", "dot1dTpLearnedEntryDiscards"), ("BRIDGE-MIB", "dot1dTpAgingTime"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dTpBridgeGroup = dot1dTpBridgeGroup.setStatus('current')
dot1dTpFdbGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 8)).setObjects(("BRIDGE-MIB", "dot1dTpFdbAddress"), ("BRIDGE-MIB", "dot1dTpFdbPort"), ("BRIDGE-MIB", "dot1dTpFdbStatus"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dTpFdbGroup = dot1dTpFdbGroup.setStatus('current')
dot1dTpGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 9)).setObjects(("BRIDGE-MIB", "dot1dTpPort"), ("BRIDGE-MIB", "dot1dTpPortMaxInfo"), ("BRIDGE-MIB", "dot1dTpPortInFrames"), ("BRIDGE-MIB", "dot1dTpPortOutFrames"), ("BRIDGE-MIB", "dot1dTpPortInDiscards"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dTpGroup = dot1dTpGroup.setStatus('current')
dot1dStaticGroup = ObjectGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 10)).setObjects(("BRIDGE-MIB", "dot1dStaticAddress"), ("BRIDGE-MIB", "dot1dStaticReceivePort"), ("BRIDGE-MIB", "dot1dStaticAllowedToGoTo"), ("BRIDGE-MIB", "dot1dStaticStatus"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dStaticGroup = dot1dStaticGroup.setStatus('current')
dot1dNotificationGroup = NotificationGroup((1, 3, 6, 1, 2, 1, 17, 8, 1, 11)).setObjects(("BRIDGE-MIB", "newRoot"), ("BRIDGE-MIB", "topologyChange"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    dot1dNotificationGroup = dot1dNotificationGroup.setStatus('current')
bridgeCompliance1493 = ModuleCompliance((1, 3, 6, 1, 2, 1, 17, 8, 2, 1)).setObjects(("BRIDGE-MIB", "dot1dBaseBridgeGroup"), ("BRIDGE-MIB", "dot1dBasePortGroup"), ("BRIDGE-MIB", "dot1dStpBridgeGroup"), ("BRIDGE-MIB", "dot1dStpPortGroup"), ("BRIDGE-MIB", "dot1dTpBridgeGroup"), ("BRIDGE-MIB", "dot1dTpFdbGroup"), ("BRIDGE-MIB", "dot1dTpGroup"), ("BRIDGE-MIB", "dot1dStaticGroup"), ("BRIDGE-MIB", "dot1dNotificationGroup"))

if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    bridgeCompliance1493 = bridgeCompliance1493.setStatus('current')
bridgeCompliance4188 = ModuleCompliance((1, 3, 6, 1, 2, 1, 17, 8, 2, 2)).setObjects(("BRIDGE-MIB", "dot1dBaseBridgeGroup"), ("BRIDGE-MIB", "dot1dBasePortGroup"), ("BRIDGE-MIB", "dot1dStpBridgeGroup"), ("BRIDGE-MIB", "dot1dStpPortGroup2"), ("BRIDGE-MIB", "dot1dStpPortGroup3"), ("BRIDGE-MIB", "dot1dTpBridgeGroup"), ("BRIDGE-MIB", "dot1dTpFdbGroup"), ("BRIDGE-MIB", "dot1dTpGroup"), ("BRIDGE-MIB", "dot1dStaticGroup"), ("BRIDGE-MIB", "dot1dNotificationGroup"))

if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    bridgeCompliance4188 = bridgeCompliance4188.setStatus('current')
mibBuilder.exportSymbols("BRIDGE-MIB", dot1dStpPortState=dot1dStpPortState, dot1dTpPortEntry=dot1dTpPortEntry, dot1dGroups=dot1dGroups, dot1dStaticGroup=dot1dStaticGroup, dot1dBasePortMtuExceededDiscards=dot1dBasePortMtuExceededDiscards, bridgeCompliance1493=bridgeCompliance1493, PYSNMP_MODULE_ID=dot1dBridge, dot1dTpPort=dot1dTpPort, dot1dTpPortTable=dot1dTpPortTable, dot1dBaseType=dot1dBaseType, dot1dStaticAddress=dot1dStaticAddress, dot1dStpPortDesignatedBridge=dot1dStpPortDesignatedBridge, dot1dStpHelloTime=dot1dStpHelloTime, dot1dStaticTable=dot1dStaticTable, dot1dStpProtocolSpecification=dot1dStpProtocolSpecification, dot1dTpPortInFrames=dot1dTpPortInFrames, dot1dBasePortDelayExceededDiscards=dot1dBasePortDelayExceededDiscards, dot1dBasePortCircuit=dot1dBasePortCircuit, dot1dStpBridgeForwardDelay=dot1dStpBridgeForwardDelay, dot1dBasePortGroup=dot1dBasePortGroup, dot1dStpHoldTime=dot1dStpHoldTime, dot1dTpGroup=dot1dTpGroup, dot1dBasePortEntry=dot1dBasePortEntry, dot1dStaticStatus=dot1dStaticStatus, dot1dTpFdbTable=dot1dTpFdbTable, BridgeId=BridgeId, dot1dStpMaxAge=dot1dStpMaxAge, dot1dBasePortTable=dot1dBasePortTable, newRoot=newRoot, bridgeCompliance4188=bridgeCompliance4188, dot1dStpPortPathCost=dot1dStpPortPathCost, dot1dTpBridgeGroup=dot1dTpBridgeGroup, dot1dBaseBridgeGroup=dot1dBaseBridgeGroup, dot1dTpFdbAddress=dot1dTpFdbAddress, dot1dBaseBridgeAddress=dot1dBaseBridgeAddress, dot1dStaticReceivePort=dot1dStaticReceivePort, dot1dNotificationGroup=dot1dNotificationGroup, dot1dStatic=dot1dStatic, dot1dBaseNumPorts=dot1dBaseNumPorts, dot1dStpForwardDelay=dot1dStpForwardDelay, dot1dTpPortOutFrames=dot1dTpPortOutFrames, dot1dTpFdbStatus=dot1dTpFdbStatus, dot1dStpPortEnable=dot1dStpPortEnable, dot1dStpPortPriority=dot1dStpPortPriority, dot1dBase=dot1dBase, Timeout=Timeout, topologyChange=topologyChange, dot1dStpRootPort=dot1dStpRootPort, dot1dStpPortTable=dot1dStpPortTable, dot1dStpTimeSinceTopologyChange=dot1dStpTimeSinceTopologyChange, dot1dStpRootCost=dot1dStpRootCost, dot1dStpPortGroup=dot1dStpPortGroup, dot1dBasePort=dot1dBasePort, dot1dTp=dot1dTp, dot1dSr=dot1dSr, dot1dStpBridgeMaxAge=dot1dStpBridgeMaxAge, dot1dNotifications=dot1dNotifications, dot1dTpFdbEntry=dot1dTpFdbEntry, dot1dConformance=dot1dConformance, dot1dStpPortDesignatedCost=dot1dStpPortDesignatedCost, dot1dStpTopChanges=dot1dStpTopChanges, dot1dStpPortGroup3=dot1dStpPortGroup3, dot1dStp=dot1dStp, dot1dTpLearnedEntryDiscards=dot1dTpLearnedEntryDiscards, dot1dTpFdbPort=dot1dTpFdbPort, dot1dStpPortDesignatedRoot=dot1dStpPortDesignatedRoot, dot1dStpBridgeGroup=dot1dStpBridgeGroup, dot1dCompliances=dot1dCompliances, dot1dStpPortForwardTransitions=dot1dStpPortForwardTransitions, dot1dStpPortDesignatedPort=dot1dStpPortDesignatedPort, dot1dStpPortPathCost32=dot1dStpPortPathCost32, dot1dBasePortIfIndex=dot1dBasePortIfIndex, dot1dTpFdbGroup=dot1dTpFdbGroup, dot1dStpPortEntry=dot1dStpPortEntry, dot1dTpAgingTime=dot1dTpAgingTime, dot1dStpPort=dot1dStpPort, dot1dStpDesignatedRoot=dot1dStpDesignatedRoot, dot1dStpBridgeHelloTime=dot1dStpBridgeHelloTime, dot1dStaticEntry=dot1dStaticEntry, dot1dStaticAllowedToGoTo=dot1dStaticAllowedToGoTo, dot1dBridge=dot1dBridge, dot1dStpPriority=dot1dStpPriority, dot1dTpPortInDiscards=dot1dTpPortInDiscards, dot1dStpPortGroup2=dot1dStpPortGroup2, dot1dTpPortMaxInfo=dot1dTpPortMaxInfo)
