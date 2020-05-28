#
# PySNMP MIB module HCNUM-TC (http://snmplabs.com/pysmi)
# ASN.1 source file:///usr/share/snmp/mibs/ietf/HCNUM-TC
# Produced by pysmi-0.3.2 at Tue Apr  7 17:41:38 2020
# On host sensei platform Linux version 4.19.97-v7l+ by user nagios
# Using Python version 3.7.3 (default, Dec 20 2019, 18:57:59) 
#
OctetString, ObjectIdentifier, Integer = mibBuilder.importSymbols("ASN1", "OctetString", "ObjectIdentifier", "Integer")
NamedValues, = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
ConstraintsUnion, SingleValueConstraint, ValueRangeConstraint, ValueSizeConstraint, ConstraintsIntersection = mibBuilder.importSymbols("ASN1-REFINEMENT", "ConstraintsUnion", "SingleValueConstraint", "ValueRangeConstraint", "ValueSizeConstraint", "ConstraintsIntersection")
NotificationGroup, ModuleCompliance = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance")
mib_2, Unsigned32, Counter64, MibScalar, MibTable, MibTableRow, MibTableColumn, Counter32, iso, ModuleIdentity, TimeTicks, ObjectIdentity, Integer32, Gauge32, NotificationType, MibIdentifier, Bits, IpAddress = mibBuilder.importSymbols("SNMPv2-SMI", "mib-2", "Unsigned32", "Counter64", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "Counter32", "iso", "ModuleIdentity", "TimeTicks", "ObjectIdentity", "Integer32", "Gauge32", "NotificationType", "MibIdentifier", "Bits", "IpAddress")
DisplayString, TextualConvention = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")
hcnumTC = ModuleIdentity((1, 3, 6, 1, 2, 1, 78))
hcnumTC.setRevisions(('2000-06-08 00:00',))
if mibBuilder.loadTexts: hcnumTC.setLastUpdated('200006080000Z')
if mibBuilder.loadTexts: hcnumTC.setOrganization('IETF OPS Area')
class CounterBasedGauge64(TextualConvention, Counter64):
    status = 'current'

class ZeroBasedCounter64(TextualConvention, Counter64):
    status = 'current'

mibBuilder.exportSymbols("HCNUM-TC", hcnumTC=hcnumTC, CounterBasedGauge64=CounterBasedGauge64, PYSNMP_MODULE_ID=hcnumTC, ZeroBasedCounter64=ZeroBasedCounter64)
