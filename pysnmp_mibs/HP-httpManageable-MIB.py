#
# PySNMP MIB module HP-httpManageable-MIB (http://snmplabs.com/pysmi)
# ASN.1 source file:///Users/michal/.snmp/mibs/HP-httpManageable-MIB
# Produced by pysmi-0.3.4 at Wed Apr  1 16:56:55 2020
# On host LogicAir-MacBookAir.local platform Darwin version 19.4.0 by user michal
# Using Python version 3.7.3 (default, Dec 13 2019, 19:58:14) 
#
ObjectIdentifier, Integer, OctetString = mibBuilder.importSymbols("ASN1", "ObjectIdentifier", "Integer", "OctetString")
NamedValues, = mibBuilder.importSymbols("ASN1-ENUMERATION", "NamedValues")
SingleValueConstraint, ConstraintsUnion, ValueRangeConstraint, ValueSizeConstraint, ConstraintsIntersection = mibBuilder.importSymbols("ASN1-REFINEMENT", "SingleValueConstraint", "ConstraintsUnion", "ValueRangeConstraint", "ValueSizeConstraint", "ConstraintsIntersection")
ModuleCompliance, NotificationGroup, ObjectGroup = mibBuilder.importSymbols("SNMPv2-CONF", "ModuleCompliance", "NotificationGroup", "ObjectGroup")
Unsigned32, Integer32, ModuleIdentity, MibScalar, MibTable, MibTableRow, MibTableColumn, NotificationType, Counter32, Gauge32, iso, Bits, ObjectIdentity, MibIdentifier, enterprises, Counter64, IpAddress, TimeTicks = mibBuilder.importSymbols("SNMPv2-SMI", "Unsigned32", "Integer32", "ModuleIdentity", "MibScalar", "MibTable", "MibTableRow", "MibTableColumn", "NotificationType", "Counter32", "Gauge32", "iso", "Bits", "ObjectIdentity", "MibIdentifier", "enterprises", "Counter64", "IpAddress", "TimeTicks")
DisplayString, TextualConvention = mibBuilder.importSymbols("SNMPv2-TC", "DisplayString", "TextualConvention")
hp = MibIdentifier((1, 3, 6, 1, 4, 1, 11))
nm = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 2))
hpWebMgmt = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 2, 36))
hpHttpMgMod = ModuleIdentity((1, 3, 6, 1, 4, 1, 11, 2, 36, 1))
hpHttpMgMod.setRevisions(('1997-06-26 00:00', '1996-06-12 00:00',))
if mibBuilder.loadTexts: hpHttpMgMod.setLastUpdated('9706260000Z')
if mibBuilder.loadTexts: hpHttpMgMod.setOrganization('Hewlett-Packard Web-based Management Working Group')
class Utf8String(TextualConvention, OctetString):
    status = 'current'
    displayHint = '255a'
    subtypeSpec = OctetString.subtypeSpec + ValueSizeConstraint(0, 255)

hpHttpMgTraps = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 0))
hpHttpMgObjects = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1))
hpHttpMgGroups = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 2))
hpHttpMgCompliances = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 3))
hpHttpMgDefaults = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 1))
hpHttpMgDefaultURL = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 1, 1), Utf8String()).setMaxAccess("readwrite")
if mibBuilder.loadTexts: hpHttpMgDefaultURL.setStatus('current')
hpHttpMgNetCitizen = MibIdentifier((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2))
hpHttpMgMgmtSrvrURL = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 1), Utf8String()).setMaxAccess("readwrite")
if mibBuilder.loadTexts: hpHttpMgMgmtSrvrURL.setStatus('current')
hpHttpMgID = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 2), Utf8String()).setMaxAccess("readonly")
if mibBuilder.loadTexts: hpHttpMgID.setStatus('current')
hpHttpMgHealth = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 3), Integer32().subtype(subtypeSpec=ConstraintsUnion(SingleValueConstraint(1, 2, 3, 4, 5, 6))).clone(namedValues=NamedValues(("unknown", 1), ("information", 2), ("ok", 3), ("warning", 4), ("critical", 5), ("nonrecoverable", 6)))).setMaxAccess("readonly")
if mibBuilder.loadTexts: hpHttpMgHealth.setStatus('current')
hpHttpMgManufacturer = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 4), Utf8String()).setMaxAccess("readonly")
if mibBuilder.loadTexts: hpHttpMgManufacturer.setStatus('current')
hpHttpMgProduct = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 5), Utf8String().subtype(subtypeSpec=ValueSizeConstraint(0, 32))).setMaxAccess("readonly")
if mibBuilder.loadTexts: hpHttpMgProduct.setStatus('current')
hpHttpMgVersion = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 6), Utf8String().subtype(subtypeSpec=ValueSizeConstraint(0, 32))).setMaxAccess("readonly")
if mibBuilder.loadTexts: hpHttpMgVersion.setStatus('current')
hpHttpMgHWVersion = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 7), Utf8String().subtype(subtypeSpec=ValueSizeConstraint(0, 32))).setMaxAccess("readonly")
if mibBuilder.loadTexts: hpHttpMgHWVersion.setStatus('current')
hpHttpMgROMVersion = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 8), Utf8String().subtype(subtypeSpec=ValueSizeConstraint(0, 32))).setMaxAccess("readonly")
if mibBuilder.loadTexts: hpHttpMgROMVersion.setStatus('current')
hpHttpMgSerialNumber = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 9), Utf8String().subtype(subtypeSpec=ValueSizeConstraint(0, 32))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: hpHttpMgSerialNumber.setStatus('current')
hpHttpMgAssetNumber = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 10), Utf8String().subtype(subtypeSpec=ValueSizeConstraint(0, 32))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: hpHttpMgAssetNumber.setStatus('current')
hpHttpMgPhone = MibScalar((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 1, 2, 11), Utf8String().subtype(subtypeSpec=ValueSizeConstraint(0, 32))).setMaxAccess("readwrite")
if mibBuilder.loadTexts: hpHttpMgPhone.setStatus('current')
hpHttpMgHealthTrap = NotificationType((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 0, 1)).setObjects(("HP-httpManageable-MIB", "hpHttpMgHealth"))
if mibBuilder.loadTexts: hpHttpMgHealthTrap.setStatus('current')
hpHttpMgShutdown = NotificationType((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 0, 2))
if mibBuilder.loadTexts: hpHttpMgShutdown.setStatus('current')
hpHttpMgMinCompliance = ModuleCompliance((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 3, 1)).setObjects(("HP-httpManageable-MIB", "hpHttpMgDefaultGroup"))

if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    hpHttpMgMinCompliance = hpHttpMgMinCompliance.setStatus('current')
hpHttpMgBasicNetCitizenCompliance = ModuleCompliance((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 3, 2)).setObjects(("HP-httpManageable-MIB", "hpHttpMgDefaultGroup"), ("HP-httpManageable-MIB", "hpHttpMgBasicNetCitizenGroup"), ("HP-httpManageable-MIB", "hpHttpMgBasicNetCitizenTrapGroup"))

if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    hpHttpMgBasicNetCitizenCompliance = hpHttpMgBasicNetCitizenCompliance.setStatus('current')
hpHttpMgDefaultGroup = ObjectGroup((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 2, 1)).setObjects(("HP-httpManageable-MIB", "hpHttpMgDefaultURL"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    hpHttpMgDefaultGroup = hpHttpMgDefaultGroup.setStatus('current')
hpHttpMgBasicNetCitizenGroup = ObjectGroup((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 2, 2)).setObjects(("HP-httpManageable-MIB", "hpHttpMgMgmtSrvrURL"), ("HP-httpManageable-MIB", "hpHttpMgID"), ("HP-httpManageable-MIB", "hpHttpMgHealth"), ("HP-httpManageable-MIB", "hpHttpMgManufacturer"), ("HP-httpManageable-MIB", "hpHttpMgProduct"), ("HP-httpManageable-MIB", "hpHttpMgVersion"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    hpHttpMgBasicNetCitizenGroup = hpHttpMgBasicNetCitizenGroup.setStatus('current')
hpHttpMgBasicNetCitizenTrapGroup = NotificationGroup((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 2, 3)).setObjects(("HP-httpManageable-MIB", "hpHttpMgHealthTrap"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    hpHttpMgBasicNetCitizenTrapGroup = hpHttpMgBasicNetCitizenTrapGroup.setStatus('current')
hpHttpMgExtendedNetCitizenGroup = ObjectGroup((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 2, 4)).setObjects(("HP-httpManageable-MIB", "hpHttpMgHWVersion"), ("HP-httpManageable-MIB", "hpHttpMgROMVersion"), ("HP-httpManageable-MIB", "hpHttpMgSerialNumber"), ("HP-httpManageable-MIB", "hpHttpMgAssetNumber"), ("HP-httpManageable-MIB", "hpHttpMgPhone"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    hpHttpMgExtendedNetCitizenGroup = hpHttpMgExtendedNetCitizenGroup.setStatus('current')
hpHttpMgExtendedNetCitizenTrapGroup = NotificationGroup((1, 3, 6, 1, 4, 1, 11, 2, 36, 1, 2, 5)).setObjects(("HP-httpManageable-MIB", "hpHttpMgShutdown"))
if getattr(mibBuilder, 'version', (0, 0, 0)) > (4, 4, 0):
    hpHttpMgExtendedNetCitizenTrapGroup = hpHttpMgExtendedNetCitizenTrapGroup.setStatus('current')
mibBuilder.exportSymbols("HP-httpManageable-MIB", hpHttpMgGroups=hpHttpMgGroups, hpHttpMgID=hpHttpMgID, hpHttpMgExtendedNetCitizenGroup=hpHttpMgExtendedNetCitizenGroup, hpHttpMgDefaultGroup=hpHttpMgDefaultGroup, hpHttpMgTraps=hpHttpMgTraps, hpHttpMgPhone=hpHttpMgPhone, hpHttpMgHealth=hpHttpMgHealth, hpHttpMgBasicNetCitizenCompliance=hpHttpMgBasicNetCitizenCompliance, hpHttpMgMinCompliance=hpHttpMgMinCompliance, hpHttpMgDefaults=hpHttpMgDefaults, hpHttpMgHWVersion=hpHttpMgHWVersion, hpHttpMgROMVersion=hpHttpMgROMVersion, hpHttpMgBasicNetCitizenTrapGroup=hpHttpMgBasicNetCitizenTrapGroup, hpHttpMgBasicNetCitizenGroup=hpHttpMgBasicNetCitizenGroup, hpHttpMgShutdown=hpHttpMgShutdown, hp=hp, hpHttpMgCompliances=hpHttpMgCompliances, hpHttpMgDefaultURL=hpHttpMgDefaultURL, Utf8String=Utf8String, hpHttpMgAssetNumber=hpHttpMgAssetNumber, hpHttpMgMod=hpHttpMgMod, hpHttpMgMgmtSrvrURL=hpHttpMgMgmtSrvrURL, hpHttpMgNetCitizen=hpHttpMgNetCitizen, hpHttpMgHealthTrap=hpHttpMgHealthTrap, hpHttpMgVersion=hpHttpMgVersion, hpHttpMgExtendedNetCitizenTrapGroup=hpHttpMgExtendedNetCitizenTrapGroup, hpHttpMgProduct=hpHttpMgProduct, hpHttpMgObjects=hpHttpMgObjects, hpWebMgmt=hpWebMgmt, hpHttpMgSerialNumber=hpHttpMgSerialNumber, hpHttpMgManufacturer=hpHttpMgManufacturer, PYSNMP_MODULE_ID=hpHttpMgMod, nm=nm)
