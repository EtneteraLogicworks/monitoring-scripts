#
# PySNMP MIB module HP-REF-MIB (http://snmplabs.com/pysmi)
# ASN.1 source file:///Users/michal/.snmp/mibs/HP-REF-MIB
# Produced by pysmi-0.3.4 at Tue Apr  7 12:27:09 2020
# On host LogicAir-MacBookAir.local platform Darwin version 19.4.0 by user michal
# Using Python version 3.7.3 (default, Mar  6 2020, 22:34:30) 
#
Integer, OctetString, ObjectIdentifier = mibBuilder.importSymbols("ASN1", "Integer", "OctetString", "ObjectIdentifier")
NamedValues, = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
ValueRangeConstraint, ConstraintsIntersection, SingleValueConstraint, ValueSizeConstraint, ConstraintsUnion = mibBuilder.importSymbols("ASN1-REFINEMENT", "ValueRangeConstraint", "ConstraintsIntersection", "SingleValueConstraint", "ValueSizeConstraint", "ConstraintsUnion")
NotificationGroup, ModuleCompliance = mibBuilder.importSymbols("SNMPv2-CONF", "NotificationGroup", "ModuleCompliance")
Gauge32, IpAddress, Bits, MibIdentifier, MibScalar, MibTable, MibTableRow, MibTableColumn, TimeTicks, Counter32, Integer32, NotificationType, enterprises, ObjectIdentity, ModuleIdentity, Unsigned32, iso, Counter64 = mibBuilder.importSymbols("SNMPv2-SMI", "Gauge32", "IpAddress", "Bits", "MibIdentifier", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "TimeTicks", "Counter32", "Integer32", "NotificationType", "enterprises", "ObjectIdentity", "ModuleIdentity", "Unsigned32", "iso", "Counter64")
TextualConvention, DisplayString = mibBuilder.importSymbols("SNMPv2-TC", "TextualConvention", "DisplayString")
hp = ModuleIdentity((1, 3, 6, 1, 4, 1, 11))
hp.setRevisions(('2007-05-23 00:00', '2003-11-21 00:00', '2003-02-06 12:00',))
if mibBuilder.loadTexts: hp.setLastUpdated('200705230000Z')
if mibBuilder.loadTexts: hp.setOrganization('HP')
hpSysMgt = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 5))
hpEmbeddedServerMgt = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 5, 7))
hpModuleMgmtProc = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 5, 7, 5))
hpHyperscaleFabric = ObjectIdentity((1, 3, 6, 1, 4, 1, 11, 5, 7, 5, 7))
if mibBuilder.loadTexts: hpHyperscaleFabric.setStatus('current')
hpGeminiFabric = ObjectIdentity((1, 3, 6, 1, 4, 1, 11, 5, 7, 5, 7, 1))
if mibBuilder.loadTexts: hpGeminiFabric.setStatus('current')
atlantis = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 5, 7, 5, 7, 1, 1))
class AgentPortMask(TextualConvention, OctetString):
    status = 'current'

mibBuilder.exportSymbols("HP-REF-MIB", atlantis=atlantis, AgentPortMask=AgentPortMask, hpSysMgt=hpSysMgt, hpEmbeddedServerMgt=hpEmbeddedServerMgt, hpModuleMgmtProc=hpModuleMgmtProc, hpHyperscaleFabric=hpHyperscaleFabric, PYSNMP_MODULE_ID=hp, hpGeminiFabric=hpGeminiFabric, hp=hp)
