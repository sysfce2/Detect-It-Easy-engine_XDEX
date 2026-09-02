/* Copyright (c) 2019-2026 hors<horsicq@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "xdex.h"

#include <cstring>

namespace {
struct DEX_VERSION_API {
    const char *pszVersion;
    qint32 nApi;
};

// Sign-extend the low nBytes of a little-endian-assembled value.
qint64 signExtendLE(quint64 nRaw, qint32 nBytes)
{
    if ((nBytes <= 0) || (nBytes >= 8)) {
        return (qint64)nRaw;
    }

    qint32 nBits = 8 * nBytes;
    quint64 nMask = (quint64)1 << (nBits - 1);

    return (qint64)((nRaw ^ nMask) - nMask);
}

quint32 readDexHeaderValue(XDEX *pDex, qint64 nFieldOffset, bool bIsBigEndian)
{
    return pDex->read_uint32(nFieldOffset, bIsBigEndian);
}

void writeDexHeaderValue(XDEX *pDex, qint64 nFieldOffset, quint32 nValue, bool bIsBigEndian)
{
    pDex->write_uint32(nFieldOffset, nValue, bIsBigEndian);
}

quint32 readDexHeaderValueAt(XDEX *pDex, qint64 nHeaderOffset, qint64 nFieldOffset, bool bIsBigEndian)
{
    return pDex->read_uint32(nHeaderOffset + nFieldOffset, bIsBigEndian);
}

bool appendDexRegion(QList<XBinary::FPART> *pList, const QString &sName, qint64 nOffset, qint64 nSize, qint32 nLimit)
{
    if (nSize) {
        pList->append(XBinary::getFPART(XBinary::FILEPART_REGION, sName, nOffset, nSize, XADDR_MAX, 0));
    }

    return (nLimit != -1) && (pList->count() >= nLimit);
}

// Clamp a declared element count to what the file can actually hold for a fixed-size
// on-disk table located at nOffset. Guards the nCount-driven, per-iteration device-read
// loops (getStrings, getTypeItemStrings, isStringPoolSorted) against a crafted count.
quint32 clampTableCount(quint32 nDeclared, qint64 nOffset, qint64 nEntrySize, qint64 nFileSize)
{
    if ((nOffset <= 0) || (nEntrySize <= 0) || (nOffset >= nFileSize)) {
        return 0;
    }

    qint64 nMax = (nFileSize - nOffset) / nEntrySize;

    if (nMax < 0) {
        nMax = 0;
    }

    return static_cast<quint32>(qMin<qint64>(static_cast<qint64>(nDeclared), nMax));
}
}  // namespace

XBinary::XIDSTRING _TABLE_XDEX_Types[] = {
    {0x0000, "HEADER_ITEM"},
    {0x0001, "STRING_ID_ITEM"},
    {0x0002, "TYPE_ID_ITEM"},
    {0x0003, "PROTO_ID_ITEM"},
    {0x0004, "FIELD_ID_ITEM"},
    {0x0005, "METHOD_ID_ITEM"},
    {0x0006, "CLASS_DEF_ITEM"},
    {0x0007, "CALL_SITE_ID_ITEM"},
    {0x0008, "METHOD_HANDLE_ITEM"},
    {0x1000, "MAP_LIST"},
    {0x1001, "TYPE_LIST"},
    {0x1002, "ANNOTATION_SET_REF_LIST"},
    {0x1003, "ANNOTATION_SET_ITEM"},
    {0x2000, "CLASS_DATA_ITEM"},
    {0x2001, "CODE_ITEM"},
    {0x2002, "STRING_DATA_ITEM"},
    {0x2003, "DEBUG_INFO_ITEM"},
    {0x2004, "ANNOTATION_ITEM"},
    {0x2005, "ENCODED_ARRAY_ITEM"},
    {0x2006, "ANNOTATIONS_DIRECTORY_ITEM"},
    {0xF000, "HIDDENAPI_CLASS_DATA_ITEM"},
};

XBinary::XIDSTRING _TABLE_XDEX_HeaderMagics[] = {
    {0x0A786564, "Magic"},
};

XBinary::XIDSTRING _TABLE_XDEX_HeaderVersions[] = {
    {0x00353330, "035"}, {0x00373330, "037"}, {0x00383330, "038"}, {0x00393330, "039"}, {0x00303430, "040"},
};

XBinary::XIDSTRING _TABLE_XDEX_HeaderEndianTags[] = {
    {0x12345678, "Little endian"},
    {0x78563412, "Big endian"},
};

const QString XDEX::PREFIX_Type = "TYPE";

XBinary::XCONVERT _TABLE_DEX_STRUCTID[] = {{XDEX::STRUCTID_UNKNOWN, "Unknown", QObject::tr("Unknown")},
                                           {XDEX::STRUCTID_HEADER, "HEADER", "HEADER"},
                                           {XDEX::STRUCTID_STRING_IDS_LIST, "STRING_IDS_LIST", "STRING_IDS_LIST"},
                                           {XDEX::STRUCTID_TYPE_IDS_LIST, "TYPE_IDS_LIST", "TYPE_IDS_LIST"},
                                           {XDEX::STRUCTID_PROTO_IDS_LIST, "PROTO_IDS_LIST", "PROTO_IDS_LIST"},
                                           {XDEX::STRUCTID_FIELD_IDS_LIST, "FIELD_IDS_LIST", "FIELD_IDS_LIST"},
                                           {XDEX::STRUCTID_METHOD_IDS_LIST, "METHOD_IDS_LIST", "METHOD_IDS_LIST"},
                                           {XDEX::STRUCTID_CLASS_DEFS_LIST, "CLASS_DEFS_LIST", "CLASS_DEFS_LIST"},
                                           {XDEX::STRUCTID_DATA_LIST, "DATA_LIST", "DATA_LIST"},
                                           {XDEX::STRUCTID_LINK_LIST, "LINK_LIST", "LINK_LIST"},
                                           {XDEX::STRUCTID_MAP_LIST, "MAP_LIST", "MAP_LIST"},
                                           {XDEX::STRUCTID_CALL_SITE_IDS_LIST, "CALL_SITE_IDS_LIST", "CALL_SITE_IDS_LIST"},
                                           {XDEX::STRUCTID_METHOD_HANDLE_LIST, "METHOD_HANDLE_LIST", "METHOD_HANDLE_LIST"}};

XDEX::XDEX(QIODevice *pDevice) : XBinary(pDevice)
{
}

XDEX::~XDEX()
{
}

XBinary::MODE XDEX::getMode(QIODevice *pDevice)
{
    XDEX xdex(pDevice);

    return xdex.getMode();
}

bool XDEX::isValid(PDSTRUCT *pPdStruct)
{
    bool bIsValid = false;

    // TODO More checks(sizes,mb hashes)

    _MEMORY_MAP memoryMap = XBinary::getSimpleMemoryMap();
    bIsValid = compareSignature(&memoryMap, "'dex\n'......00", 0, pPdStruct);

    if (bIsValid) {
        bIsValid = (_getVersion() >= 35);
    }

    return bIsValid;
}

bool XDEX::isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct)
{
    XDEX xdex(pDevice);

    return xdex.isValid(pPdStruct);
}

quint32 XDEX::_getVersion()
{
    return getVersion().toUInt();
}

QString XDEX::getVersion()
{
    return read_ansiString(4);  // TODO Check
}

XBinary::ENDIAN XDEX::getEndian()
{
    ENDIAN result = ENDIAN_UNKNOWN;

    quint32 nData = read_uint32(offsetof(XDEX_DEF::HEADER, endian_tag));

    if (nData == 0x12345678) {
        result = ENDIAN_LITTLE;
    } else if (nData == 0x78563412) {
        result = ENDIAN_BIG;
    }

    return result;
}

XBinary::MODE XDEX::getMode()
{
    return MODE_32;
}

QString XDEX::getArch()
{
    return QString("Dalvik");  // TODO Check
}

bool XDEX::isExecutable()
{
    return true;  // DEX is Dalvik executable bytecode
}

QString XDEX::getOsVersion()
{
    QString sDEXVersion = getVersion();
    static const DEX_VERSION_API versions[] = {
        {"035", 14}, {"037", 24},  // 036 was skipped due to a Dalvik bug; it is not valid for any Android version
        {"038", 26}, {"039", 28}, {"040", 29},
    };

    // https://source.android.com/devices/tech/dalvik/dex-format
    for (quint32 i = 0; i < sizeof(versions) / sizeof(versions[0]); ++i) {
        if (sDEXVersion == QLatin1String(versions[i].pszVersion)) {
            return XBinary::getAndroidVersionFromApi(versions[i].nApi);  // TODO move the function here
        }
    }

    return sDEXVersion;
}

XBinary::OSNAME XDEX::getOsName()
{
    return OSNAME_ANDROID;
}

XBinary::FT XDEX::getFileType()
{
    return FT_DEX;
}

qint32 XDEX::getType()
{
    // TODO more (main module,second module etc)
    return TYPE_MAINMODULE;
}

QString XDEX::typeIdToString(qint32 nType)
{
    QString sResult = tr("Unknown");

    switch (nType) {
        case TYPE_UNKNOWN: sResult = tr("Unknown"); break;
        case TYPE_MAINMODULE: sResult = tr("Main module"); break;
    }

    return sResult;
}

QString XDEX::getInfo(PDSTRUCT *pPdStruct)
{
    QString sResult;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    if (!progressLifetime.isValid()) return sResult;

    QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(pPdStruct);
    if (!isPdStructLifetimeAlive(progressLifetime)) return {};
    if (!listMapItems.isEmpty() && XBinary::isPdStructNotCanceled(pPdStruct)) {
        sResult = XBinary::valueToHex(getMapItemsHash(&listMapItems, pPdStruct), false);
        if (!isPdStructLifetimeAlive(progressLifetime)) return {};
    }

    return sResult;
}

bool XDEX::isImportPresent()
{
    const QVector<XSYMBOL_STRUCT> listSymbols = _getSymbolStructs();

    for (const XSYMBOL_STRUCT &symbol : listSymbols) {
        if (symbol.symbolType == SYMBOL_TYPE_IMPORT) {
            return true;
        }
    }

    return false;
}

bool XDEX::isExportPresent()
{
    const QVector<XSYMBOL_STRUCT> listSymbols = _getSymbolStructs();

    for (const XSYMBOL_STRUCT &symbol : listSymbols) {
        if (symbol.symbolType == SYMBOL_TYPE_EXPORT) {
            return true;
        }
    }

    return false;
}

bool XDEX::isSymbolsPresent()
{
    return getHeader_method_ids_size() != 0;
}

QVector<XBinary::XSYMBOL_STRUCT> XDEX::_getSymbolStructs()
{
    struct DEFINED_METHOD {
        quint32 nAccessFlags;
        quint32 nCodeOffset;
    };

    QVector<XSYMBOL_STRUCT> listResult;
    PDSTRUCT pdStruct = XBinary::createPdStruct();
    QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(&pdStruct);

    if (listMapItems.isEmpty()) {
        return listResult;
    }

    const XDEX_DEF::MAP_ITEM mapMethod = getMapItem(XDEX_DEF::TYPE_METHOD_ID_ITEM, &listMapItems, &pdStruct);
    const QList<XDEX_DEF::METHOD_ITEM_ID> listMethods = getList_METHOD_ITEM_ID(&listMapItems, &pdStruct);

    if ((mapMethod.nOffset == 0) || listMethods.isEmpty()) {
        return listResult;
    }

    QMap<quint32, DEFINED_METHOD> mapDefinedMethods;
    const QList<XDEX_DEF::CLASS_ITEM_DEF> listClasses = getList_CLASS_ITEM_DEF(&listMapItems, &pdStruct);

    for (const XDEX_DEF::CLASS_ITEM_DEF &classItem : listClasses) {
        if (classItem.class_data_off == 0) {
            continue;
        }

        const CLASS_DATA classData = getClassData(classItem.class_data_off, &pdStruct);
        QList<XDEX_DEF::ENCODED_METHOD> listDefined = classData.listDirectMethods;
        listDefined.append(classData.listVirtualMethods);

        for (const XDEX_DEF::ENCODED_METHOD &method : listDefined) {
            if (method.method_idx < static_cast<quint32>(listMethods.count())) {
                DEFINED_METHOD definedMethod = {};
                definedMethod.nAccessFlags = method.access_flags;
                definedMethod.nCodeOffset = method.code_off;
                mapDefinedMethods.insert(method.method_idx, definedMethod);
            }
        }
    }

    const qint32 nNumberOfMethods = listMethods.count();
    listResult.reserve(nNumberOfMethods);

    for (qint32 i = 0; i < nNumberOfMethods; ++i) {
        XSYMBOL_STRUCT record = {};
        record.nOffset = mapMethod.nOffset + static_cast<qint64>(i) * sizeof(XDEX_DEF::METHOD_ITEM_ID);
        record.sName = getMethodString(static_cast<quint32>(i), &listMapItems, &pdStruct);

        const QMap<quint32, DEFINED_METHOD>::const_iterator it = mapDefinedMethods.constFind(static_cast<quint32>(i));
        if (it == mapDefinedMethods.constEnd()) {
            record.symbolType = SYMBOL_TYPE_IMPORT;
        } else {
            const DEFINED_METHOD &definedMethod = it.value();
            if (definedMethod.nCodeOffset != 0) {
                record.nSize = getCodeItemSize(definedMethod.nCodeOffset, &pdStruct);
                record.nAddress = offsetToAddress(definedMethod.nCodeOffset);
            }

            if (definedMethod.nAccessFlags & (XDEX_DEF::ACC_PUBLIC | XDEX_DEF::ACC_PROTECTED)) {
                record.symbolType = SYMBOL_TYPE_EXPORT;
            } else {
                record.symbolType = SYMBOL_TYPE_LABEL;
            }
        }

        listResult.append(record);
    }

    return listResult;
}

QVector<XBinary::XSYMBOL_STRUCT> XDEX::getSymbolStructs()
{
    return _getSymbolStructs();
}

QVector<XBinary::XIMPORT_STRUCT> XDEX::getImportStructs()
{
    QVector<XIMPORT_STRUCT> listResult;
    PDSTRUCT pdStruct = XBinary::createPdStruct();
    QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(&pdStruct);

    if (listMapItems.isEmpty()) {
        return listResult;
    }

    const XDEX_DEF::MAP_ITEM mapMethod = getMapItem(XDEX_DEF::TYPE_METHOD_ID_ITEM, &listMapItems, &pdStruct);
    const QList<XDEX_DEF::METHOD_ITEM_ID> listMethods = getList_METHOD_ITEM_ID(&listMapItems, &pdStruct);
    const QVector<XSYMBOL_STRUCT> listSymbols = _getSymbolStructs();

    for (const XSYMBOL_STRUCT &symbol : listSymbols) {
        if ((symbol.symbolType != SYMBOL_TYPE_IMPORT) || (symbol.nOffset < mapMethod.nOffset)) {
            continue;
        }

        const qint64 nIndex = (symbol.nOffset - mapMethod.nOffset) / sizeof(XDEX_DEF::METHOD_ITEM_ID);
        if ((nIndex < 0) || (nIndex >= listMethods.count())) {
            continue;
        }

        const XDEX_DEF::METHOD_ITEM_ID &method = listMethods.at(static_cast<qint32>(nIndex));
        XIMPORT_STRUCT record = {};
        record.nOffset = symbol.nOffset;
        record.nSize = symbol.nSize;
        record.nAddress = symbol.nAddress;
        record.sLibrary = getClassString(method.class_idx, &listMapItems, &pdStruct);
        record.sFunction = symbol.sName;
        const QString sPrefix = record.sLibrary + QLatin1Char('.');
        if (record.sFunction.startsWith(sPrefix)) {
            record.sFunction.remove(0, sPrefix.size());
        }
        record.nOrdinal = static_cast<qint32>(nIndex);

        listResult.append(record);
    }

    return listResult;
}

QVector<XBinary::XEXPORT_STRUCT> XDEX::getExportStructs()
{
    QVector<XEXPORT_STRUCT> listResult;
    PDSTRUCT pdStruct = XBinary::createPdStruct();
    QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(&pdStruct);

    if (listMapItems.isEmpty()) {
        return listResult;
    }

    const XDEX_DEF::MAP_ITEM mapMethod = getMapItem(XDEX_DEF::TYPE_METHOD_ID_ITEM, &listMapItems, &pdStruct);
    const QVector<XSYMBOL_STRUCT> listSymbols = _getSymbolStructs();

    for (const XSYMBOL_STRUCT &symbol : listSymbols) {
        if ((symbol.symbolType != SYMBOL_TYPE_EXPORT) || (symbol.nOffset < mapMethod.nOffset)) {
            continue;
        }

        const qint64 nIndex = (symbol.nOffset - mapMethod.nOffset) / sizeof(XDEX_DEF::METHOD_ITEM_ID);
        if ((nIndex < 0) || (nIndex > 0x7FFFFFFF)) {
            continue;
        }

        XEXPORT_STRUCT record = {};
        record.nOffset = symbol.nOffset;
        record.nSize = symbol.nSize;
        record.nAddress = symbol.nAddress;
        record.sFunction = symbol.sName;
        record.nOrdinal = static_cast<qint32>(nIndex);

        listResult.append(record);
    }

    return listResult;
}

QList<XBinary::MAPMODE> XDEX::getMapModesList()
{
    QList<MAPMODE> listResult;

    listResult.append(MAPMODE_REGIONS);
    listResult.append(MAPMODE_SECTIONS);

    return listResult;
}

XBinary::_MEMORY_MAP XDEX::getMemoryMap(MAPMODE mapMode, PDSTRUCT *pPdStruct)
{
    XBinary::_MEMORY_MAP result = {};

    if (mapMode == MAPMODE_UNKNOWN) {
        mapMode = MAPMODE_REGIONS;  // Default mode
    }

    if (mapMode == MAPMODE_REGIONS) {
        result = _getMemoryMap(FILEPART_HEADER | FILEPART_REGION | FILEPART_OVERLAY, pPdStruct);
    } else if (mapMode == MAPMODE_SECTIONS) {
        result = _getMemoryMap(FILEPART_HEADER | FILEPART_SECTION | FILEPART_OVERLAY, pPdStruct);
    }

    return result;
}

qint64 XDEX::getFileFormatSize(PDSTRUCT *pPdStruct)
{
    qint64 nResult = 0;

    // Validate basic structure first
    if (!isValid(pPdStruct)) {
        return 0;
    }

    const qint64 nActualSize = getSize();
    const quint32 nHeaderSize = getHeader_header_size();
    const quint32 nFileSizeField = getHeader_file_size();

    // Sanity: header must not exceed actual file and must be at least the header struct
    if ((nHeaderSize < sizeof(XDEX_DEF::HEADER)) || ((qint64)nHeaderSize > nActualSize)) {
        // Fallback: unknown header, return clamped field or actual size
        return qMin<qint64>(nActualSize, (qint64)nFileSizeField);
    }

    // DEX format size should be the header's file_size; clamp to actual size and enforce header_size lower bound
    if ((nFileSizeField == 0) || (nFileSizeField < nHeaderSize)) {
        nResult = nActualSize;  // invalid field, fallback to actual
    } else {
        nResult = qMin<qint64>(nActualSize, (qint64)nFileSizeField);
    }

    return nResult;
}

quint32 XDEX::getHeader_magic()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, magic), false);
}

quint32 XDEX::getHeader_version()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, version), false);
}

quint32 XDEX::getHeader_checksum()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, checksum), isBigEndian());
}

QByteArray XDEX::getHeader_signature()
{
    return read_array(offsetof(XDEX_DEF::HEADER, signature), 20);
}

quint32 XDEX::getHeader_file_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, file_size), isBigEndian());
}

quint32 XDEX::getHeader_header_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, header_size), isBigEndian());
}

quint32 XDEX::getHeader_endian_tag()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, endian_tag), false);
}

quint32 XDEX::getHeader_link_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, link_size), isBigEndian());
}

quint32 XDEX::getHeader_link_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, link_off), isBigEndian());
}

quint32 XDEX::getHeader_map_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, map_off), isBigEndian());
}

quint32 XDEX::getHeader_string_ids_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, string_ids_size), isBigEndian());
}

quint32 XDEX::getHeader_string_ids_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, string_ids_off), isBigEndian());
}

quint32 XDEX::getHeader_type_ids_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, type_ids_size), isBigEndian());
}

quint32 XDEX::getHeader_type_ids_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, type_ids_off), isBigEndian());
}

quint32 XDEX::getHeader_proto_ids_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, proto_ids_size), isBigEndian());
}

quint32 XDEX::getHeader_proto_ids_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, proto_ids_off), isBigEndian());
}

quint32 XDEX::getHeader_field_ids_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, field_ids_size), isBigEndian());
}

quint32 XDEX::getHeader_field_ids_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, field_ids_off), isBigEndian());
}

quint32 XDEX::getHeader_method_ids_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, method_ids_size), isBigEndian());
}

quint32 XDEX::getHeader_method_ids_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, method_ids_off), isBigEndian());
}

quint32 XDEX::getHeader_class_defs_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, class_defs_size), isBigEndian());
}

quint32 XDEX::getHeader_class_defs_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, class_defs_off), isBigEndian());
}

quint32 XDEX::getHeader_data_size()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, data_size), isBigEndian());
}

quint32 XDEX::getHeader_data_off()
{
    return readDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, data_off), isBigEndian());
}

void XDEX::setHeader_magic(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, magic), value, false);
}

void XDEX::setHeader_version(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, version), value, false);
}

void XDEX::setHeader_checksum(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, checksum), value, isBigEndian());
}

void XDEX::setHeader_file_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, file_size), value, isBigEndian());
}

void XDEX::setHeader_header_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, header_size), value, isBigEndian());
}

void XDEX::setHeader_endian_tag(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, endian_tag), value, false);
}

void XDEX::setHeader_link_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, link_size), value, isBigEndian());
}

void XDEX::setHeader_link_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, link_off), value, isBigEndian());
}

void XDEX::setHeader_map_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, map_off), value, isBigEndian());
}

void XDEX::setHeader_string_ids_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, string_ids_size), value, isBigEndian());
}

void XDEX::setHeader_string_ids_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, string_ids_off), value, isBigEndian());
}

void XDEX::setHeader_type_ids_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, type_ids_size), value, isBigEndian());
}

void XDEX::setHeader_type_ids_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, type_ids_off), value, isBigEndian());
}

void XDEX::setHeader_proto_ids_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, proto_ids_size), value, isBigEndian());
}

void XDEX::setHeader_proto_ids_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, proto_ids_off), value, isBigEndian());
}

void XDEX::setHeader_field_ids_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, field_ids_size), value, isBigEndian());
}

void XDEX::setHeader_field_ids_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, field_ids_off), value, isBigEndian());
}

void XDEX::setHeader_method_ids_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, method_ids_size), value, isBigEndian());
}

void XDEX::setHeader_method_ids_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, method_ids_off), value, isBigEndian());
}

void XDEX::setHeader_class_defs_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, class_defs_size), value, isBigEndian());
}

void XDEX::setHeader_class_defs_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, class_defs_off), value, isBigEndian());
}

void XDEX::setHeader_data_size(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, data_size), value, isBigEndian());
}

void XDEX::setHeader_data_off(quint32 value)
{
    writeDexHeaderValue(this, offsetof(XDEX_DEF::HEADER, data_off), value, isBigEndian());
}

XDEX_DEF::HEADER XDEX::getHeader()
{
    return _readHEADER(0);
}

XDEX_DEF::HEADER XDEX::_readHEADER(qint64 nOffset)
{
    XDEX_DEF::HEADER result = {};

    bool bIsBigEndian = (readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, endian_tag), false) == 0x78563412);

    result.magic = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, magic), false);
    result.version = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, version), false);
    result.checksum = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, checksum), bIsBigEndian);
    result.file_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, file_size), bIsBigEndian);
    result.header_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, header_size), bIsBigEndian);
    result.endian_tag = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, endian_tag), false);
    result.link_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, link_size), bIsBigEndian);
    result.link_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, link_off), bIsBigEndian);
    result.map_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, map_off), bIsBigEndian);
    result.string_ids_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, string_ids_size), bIsBigEndian);
    result.string_ids_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, string_ids_off), bIsBigEndian);
    result.type_ids_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, type_ids_size), bIsBigEndian);
    result.type_ids_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, type_ids_off), bIsBigEndian);
    result.proto_ids_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, proto_ids_size), bIsBigEndian);
    result.proto_ids_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, proto_ids_off), bIsBigEndian);
    result.field_ids_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, field_ids_size), bIsBigEndian);
    result.field_ids_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, field_ids_off), bIsBigEndian);
    result.method_ids_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, method_ids_size), bIsBigEndian);
    result.method_ids_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, method_ids_off), bIsBigEndian);
    result.class_defs_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, class_defs_size), bIsBigEndian);
    result.class_defs_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, class_defs_off), bIsBigEndian);
    result.data_size = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, data_size), bIsBigEndian);
    result.data_off = readDexHeaderValueAt(this, nOffset, offsetof(XDEX_DEF::HEADER, data_off), bIsBigEndian);

    return result;
}

quint32 XDEX::getHeaderSize()
{
    return sizeof(XDEX_DEF::HEADER);
}

QList<XDEX_DEF::MAP_ITEM> XDEX::getMapItems(PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::MAP_ITEM> listResult;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    bool bProgressOwnerAlive = progressLifetime.isValid();
    if (!bProgressOwnerAlive) return listResult;

    qint64 nMapOff = getHeader_map_off();
    if (nMapOff == 0) {
        return listResult;
    }

    const qint64 nFileSize = getSize();
    if ((nMapOff < 0) || (nMapOff > (nFileSize - 4))) {  // need at least 4 bytes for size
        return listResult;
    }

    bool bIsBigEndian = isBigEndian();

    quint32 nDeclaredItems = read_uint32(nMapOff, bIsBigEndian);
    qint64 nOffset = nMapOff + sizeof(quint32);

    // Compute maximum possible entries given file size to avoid OOB
    qint64 nAvail = nFileSize - nOffset;
    qint64 nMaxItemsBySize = (nAvail >= 0) ? (nAvail / sizeof(XDEX_DEF::MAP_ITEM)) : 0;
    quint32 nItems = static_cast<quint32>(qMin<qint64>(nDeclaredItems, qMin<qint64>(nMaxItemsBySize, 0x10000)));

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nItems);

    for (quint32 i = 0; bProgressOwnerAlive && (i < nItems) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XDEX_DEF::MAP_ITEM map_item = {};

        map_item.nType = read_uint16(nOffset, bIsBigEndian);
        // skip 2 bytes reserved/unused at +2
        map_item.nCount = read_uint32(nOffset + offsetof(XDEX_DEF::MAP_ITEM, nCount), bIsBigEndian);
        map_item.nOffset = read_uint32(nOffset + offsetof(XDEX_DEF::MAP_ITEM, nOffset), bIsBigEndian);

        listResult.append(map_item);

        nOffset += sizeof(XDEX_DEF::MAP_ITEM);

        bProgressOwnerAlive = XBinary::setPdStructCurrentIncrementChecked(pPdStruct, _nFreeIndex, progressLifetime);
        if (!bProgressOwnerAlive) return {};
    }

    if (bProgressOwnerAlive) {
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }

    return listResult;
}

bool XDEX::compareMapItems(QList<XDEX_DEF::MAP_ITEM> *pListMaps, QList<quint16> *pListIDs, PDSTRUCT *pPdStruct)
{
    bool bResult = false;

    qint32 nNumberOfMapItems = pListMaps->count();
    qint32 nNumberOfIDs = pListIDs->count();

    qint32 nCurrentMapItem = 0;
    qint32 nCurrentID = 0;

    while ((nCurrentMapItem < nNumberOfMapItems) && (nCurrentID < nNumberOfIDs) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        bResult = false;

        if (pListMaps->at(nCurrentMapItem).nType == pListIDs->at(nCurrentID)) {
            bResult = true;
            nCurrentMapItem++;
            nCurrentID++;
        } else {
            nCurrentID++;
        }
    }

    bResult = (bResult) && (nCurrentMapItem == qMin(nNumberOfMapItems, nNumberOfIDs));

    return bResult;
}

quint32 XDEX::getMapItemsHash(QList<XDEX_DEF::MAP_ITEM> *pListMaps, PDSTRUCT *pPdStruct)
{
    quint32 nResult = 0;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    bool bProgressOwnerAlive = progressLifetime.isValid();
    if (!bProgressOwnerAlive) return 0;

    if (!pListMaps) {
        return 0;
    }

    const qint32 nCount = pListMaps->count();

    // Initialize CRC32 (EDB88320) with standard init value
    quint32 nCrc = 0xFFFFFFFF;
    quint32 *pTable = XBinary::_getCRC32Table_EDB88320();

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nCount);

    for (qint32 i = 0; bProgressOwnerAlive && (i < nCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        const XDEX_DEF::MAP_ITEM &mi = pListMaps->at(i);

        // Serialize only the type (sequence of types) in little-endian order
        char b16[2] = {static_cast<char>(mi.nType & 0xFF), static_cast<char>((mi.nType >> 8) & 0xFF)};

        nCrc = XBinary::_getCRC32(b16, 2, nCrc, pTable);

        bProgressOwnerAlive = XBinary::setPdStructCurrentIncrementChecked(pPdStruct, _nFreeIndex, progressLifetime);
        if (!bProgressOwnerAlive) return 0;
    }

    if (bProgressOwnerAlive) {
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }

    if (XBinary::isPdStructStopped(pPdStruct)) {
        return 0;
    }

    // Finalize CRC
    nResult = nCrc ^ 0xFFFFFFFF;

    return nResult;
}

bool XDEX::isMapItemPresent(quint16 nType, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    bool bResult = false;

    qint32 nNumberOfItems = pMapItems->count();

    for (qint32 i = 0; (i < nNumberOfItems) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if (pMapItems->at(i).nType == nType) {
            bResult = true;

            break;
        }
    }

    return bResult;
}

QMap<quint64, QString> XDEX::getTypes()
{
    return XBinary::XIDSTRING_createMapPrefix(_TABLE_XDEX_Types, sizeof(_TABLE_XDEX_Types) / sizeof(XBinary::XIDSTRING), PREFIX_Type);
}

QMap<quint64, QString> XDEX::getTypesS()
{
    return XBinary::XIDSTRING_createMap(_TABLE_XDEX_Types, sizeof(_TABLE_XDEX_Types) / sizeof(XBinary::XIDSTRING));
}

XDEX_DEF::MAP_ITEM XDEX::getMapItem(quint16 nType, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    XDEX_DEF::MAP_ITEM result = {};

    qint32 nCount = pMapItems->count();

    for (qint32 i = 0; (i < nCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if (pMapItems->at(i).nType == nType) {
            result = pMapItems->at(i);

            break;
        }
    }

    return result;
}

QList<XDEX_DEF::STRING_ITEM_ID> XDEX::getList_STRING_ITEM_ID(PDSTRUCT *pPdStruct)
{
    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    if (!progressLifetime.isValid()) return {};

    QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(pPdStruct);
    if (!isPdStructLifetimeAlive(progressLifetime)) return {};

    return getList_STRING_ITEM_ID(&listMapItems, pPdStruct);
}

QList<XDEX_DEF::STRING_ITEM_ID> XDEX::getList_STRING_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::STRING_ITEM_ID> listResult;

    bool bIsBigEndian = isBigEndian();

    XDEX_DEF::MAP_ITEM mapItem = getMapItem(XDEX_DEF::TYPE_STRING_ID_ITEM, pListMapItems, pPdStruct);

    QByteArray baData = read_array_process(mapItem.nOffset, mapItem.nCount * sizeof(XDEX_DEF::STRING_ITEM_ID), pPdStruct);
    char *pData = baData.data();
    qint32 nSize = baData.size() / (qint32)sizeof(XDEX_DEF::STRING_ITEM_ID);

    for (qint32 i = 0; (i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = sizeof(XDEX_DEF::STRING_ITEM_ID) * i;

        XDEX_DEF::STRING_ITEM_ID record = {};

        record.string_data_off = _read_int32(pData + nOffset + offsetof(XDEX_DEF::STRING_ITEM_ID, string_data_off), bIsBigEndian);

        listResult.append(record);
    }

    return listResult;
}

QList<XDEX_DEF::TYPE_ITEM_ID> XDEX::getList_TYPE_ITEM_ID(PDSTRUCT *pPdStruct)
{
    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    if (!progressLifetime.isValid()) return {};

    QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(pPdStruct);
    if (!isPdStructLifetimeAlive(progressLifetime)) return {};

    return getList_TYPE_ITEM_ID(&listMapItems, pPdStruct);
}

QList<XDEX_DEF::TYPE_ITEM_ID> XDEX::getList_TYPE_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::TYPE_ITEM_ID> listResult;

    XDEX_DEF::MAP_ITEM mapItem = getMapItem(XDEX_DEF::TYPE_TYPE_ID_ITEM, pListMapItems, pPdStruct);
    bool bIsBigEndian = isBigEndian();

    QByteArray baData = read_array_process(mapItem.nOffset, mapItem.nCount * sizeof(XDEX_DEF::TYPE_ITEM_ID), pPdStruct);
    char *pData = baData.data();
    qint32 nSize = baData.size() / (qint32)sizeof(XDEX_DEF::TYPE_ITEM_ID);

    for (qint32 i = 0; (i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = sizeof(XDEX_DEF::TYPE_ITEM_ID) * i;

        XDEX_DEF::TYPE_ITEM_ID record = {};

        record.descriptor_idx = _read_int32(pData + nOffset + offsetof(XDEX_DEF::TYPE_ITEM_ID, descriptor_idx), bIsBigEndian);

        listResult.append(record);
    }

    return listResult;
}

QList<XDEX_DEF::PROTO_ITEM_ID> XDEX::getList_PROTO_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::PROTO_ITEM_ID> listResult;

    XDEX_DEF::MAP_ITEM mapItem = getMapItem(XDEX_DEF::TYPE_PROTO_ID_ITEM, pListMapItems, pPdStruct);
    bool bIsBigEndian = isBigEndian();

    QByteArray baData = read_array_process(mapItem.nOffset, mapItem.nCount * sizeof(XDEX_DEF::PROTO_ITEM_ID), pPdStruct);
    char *pData = baData.data();
    qint32 nSize = baData.size() / (qint32)sizeof(XDEX_DEF::PROTO_ITEM_ID);

    for (qint32 i = 0; (i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = sizeof(XDEX_DEF::PROTO_ITEM_ID) * i;

        XDEX_DEF::PROTO_ITEM_ID record = {};

        record.shorty_idx = _read_int32(pData + nOffset + offsetof(XDEX_DEF::PROTO_ITEM_ID, shorty_idx), bIsBigEndian);
        record.return_type_idx = _read_int32(pData + nOffset + offsetof(XDEX_DEF::PROTO_ITEM_ID, return_type_idx), bIsBigEndian);
        record.parameters_off = _read_int32(pData + nOffset + offsetof(XDEX_DEF::PROTO_ITEM_ID, parameters_off), bIsBigEndian);

        listResult.append(record);
    }

    return listResult;
}

QList<XDEX_DEF::FIELD_ITEM_ID> XDEX::getList_FIELD_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::FIELD_ITEM_ID> listResult;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    bool bProgressOwnerAlive = progressLifetime.isValid();
    if (!bProgressOwnerAlive) return listResult;

    XDEX_DEF::MAP_ITEM mapItem = getMapItem(XDEX_DEF::TYPE_FIELD_ID_ITEM, pListMapItems, pPdStruct);
    bool bIsBigEndian = isBigEndian();

    QByteArray baData = read_array_process(mapItem.nOffset, mapItem.nCount * sizeof(XDEX_DEF::FIELD_ITEM_ID), pPdStruct);
    bProgressOwnerAlive = isPdStructLifetimeAlive(progressLifetime);
    if (!bProgressOwnerAlive) return {};
    char *pData = baData.data();
    qint32 nSize = baData.size() / (qint32)sizeof(XDEX_DEF::FIELD_ITEM_ID);

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nSize);

    for (qint32 i = 0; bProgressOwnerAlive && (i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = sizeof(XDEX_DEF::FIELD_ITEM_ID) * i;

        XDEX_DEF::FIELD_ITEM_ID record = {};

        record.class_idx = _read_int16(pData + nOffset + offsetof(XDEX_DEF::FIELD_ITEM_ID, class_idx), bIsBigEndian);
        record.type_idx = _read_int16(pData + nOffset + offsetof(XDEX_DEF::FIELD_ITEM_ID, type_idx), bIsBigEndian);
        record.name_idx = _read_int32(pData + nOffset + offsetof(XDEX_DEF::FIELD_ITEM_ID, name_idx), bIsBigEndian);

        listResult.append(record);

        bProgressOwnerAlive = XBinary::setPdStructCurrentIncrementChecked(pPdStruct, _nFreeIndex, progressLifetime);
        if (!bProgressOwnerAlive) return {};
    }

    if (bProgressOwnerAlive) {
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }

    return listResult;
}

QList<XDEX_DEF::METHOD_ITEM_ID> XDEX::getList_METHOD_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::METHOD_ITEM_ID> listResult;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    bool bProgressOwnerAlive = progressLifetime.isValid();
    if (!bProgressOwnerAlive) return listResult;

    XDEX_DEF::MAP_ITEM mapItem = getMapItem(XDEX_DEF::TYPE_METHOD_ID_ITEM, pListMapItems, pPdStruct);
    bool bIsBigEndian = isBigEndian();

    QByteArray baData = read_array_process(mapItem.nOffset, mapItem.nCount * sizeof(XDEX_DEF::METHOD_ITEM_ID), pPdStruct);
    bProgressOwnerAlive = isPdStructLifetimeAlive(progressLifetime);
    if (!bProgressOwnerAlive) return {};
    char *pData = baData.data();
    qint32 nSize = baData.size() / (qint32)sizeof(XDEX_DEF::METHOD_ITEM_ID);

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nSize);

    for (qint32 i = 0; bProgressOwnerAlive && (i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = sizeof(XDEX_DEF::METHOD_ITEM_ID) * i;

        XDEX_DEF::METHOD_ITEM_ID record = {};

        record.class_idx = _read_int16(pData + nOffset + offsetof(XDEX_DEF::METHOD_ITEM_ID, class_idx), bIsBigEndian);
        record.proto_idx = _read_int16(pData + nOffset + offsetof(XDEX_DEF::METHOD_ITEM_ID, proto_idx), bIsBigEndian);
        record.name_idx = _read_int32(pData + nOffset + offsetof(XDEX_DEF::METHOD_ITEM_ID, name_idx), bIsBigEndian);

        listResult.append(record);

        bProgressOwnerAlive = XBinary::setPdStructCurrentIncrementChecked(pPdStruct, _nFreeIndex, progressLifetime);
        if (!bProgressOwnerAlive) return {};
    }

    if (bProgressOwnerAlive) {
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }

    return listResult;
}

QList<XDEX_DEF::CLASS_ITEM_DEF> XDEX::getList_CLASS_ITEM_DEF(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::CLASS_ITEM_DEF> listResult;

    XDEX_DEF::MAP_ITEM mapItem = getMapItem(XDEX_DEF::TYPE_CLASS_DEF_ITEM, pListMapItems, pPdStruct);
    bool bIsBigEndian = isBigEndian();

    QByteArray baData = read_array_process(mapItem.nOffset, mapItem.nCount * sizeof(XDEX_DEF::CLASS_ITEM_DEF), pPdStruct);
    char *pData = baData.data();
    qint32 nSize = baData.size() / (qint32)sizeof(XDEX_DEF::CLASS_ITEM_DEF);

    for (qint32 i = 0; (i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = sizeof(XDEX_DEF::CLASS_ITEM_DEF) * i;

        XDEX_DEF::CLASS_ITEM_DEF record = {};

        record.class_idx = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CLASS_ITEM_DEF, class_idx), bIsBigEndian);
        record.access_flags = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CLASS_ITEM_DEF, access_flags), bIsBigEndian);
        record.superclass_idx = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CLASS_ITEM_DEF, superclass_idx), bIsBigEndian);
        record.interfaces_off = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CLASS_ITEM_DEF, interfaces_off), bIsBigEndian);
        record.source_file_idx = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CLASS_ITEM_DEF, source_file_idx), bIsBigEndian);
        record.annotations_off = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CLASS_ITEM_DEF, annotations_off), bIsBigEndian);
        record.class_data_off = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CLASS_ITEM_DEF, class_data_off), bIsBigEndian);
        record.static_values_off = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CLASS_ITEM_DEF, static_values_off), bIsBigEndian);

        listResult.append(record);
    }

    return listResult;
}

QList<XDEX_DEF::CALL_SITE_ITEM_ID> XDEX::getList_CALL_SITE_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::CALL_SITE_ITEM_ID> listResult;

    XDEX_DEF::MAP_ITEM mapItem = getMapItem(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM, pListMapItems, pPdStruct);
    bool bIsBigEndian = isBigEndian();

    QByteArray baData = read_array_process(mapItem.nOffset, (qint64)mapItem.nCount * sizeof(XDEX_DEF::CALL_SITE_ITEM_ID), pPdStruct);
    char *pData = baData.data();
    qint32 nSize = baData.size() / (qint32)sizeof(XDEX_DEF::CALL_SITE_ITEM_ID);

    for (qint32 i = 0; (i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = sizeof(XDEX_DEF::CALL_SITE_ITEM_ID) * i;

        XDEX_DEF::CALL_SITE_ITEM_ID record = {};

        record.call_site_off = _read_int32(pData + nOffset + offsetof(XDEX_DEF::CALL_SITE_ITEM_ID, call_site_off), bIsBigEndian);

        listResult.append(record);
    }

    return listResult;
}

QList<XDEX_DEF::METHOD_HANDLE_ITEM> XDEX::getList_METHOD_HANDLE_ITEM(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct)
{
    QList<XDEX_DEF::METHOD_HANDLE_ITEM> listResult;

    XDEX_DEF::MAP_ITEM mapItem = getMapItem(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM, pListMapItems, pPdStruct);
    bool bIsBigEndian = isBigEndian();

    QByteArray baData = read_array_process(mapItem.nOffset, (qint64)mapItem.nCount * sizeof(XDEX_DEF::METHOD_HANDLE_ITEM), pPdStruct);
    char *pData = baData.data();
    qint32 nSize = baData.size() / (qint32)sizeof(XDEX_DEF::METHOD_HANDLE_ITEM);

    for (qint32 i = 0; (i < nSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = sizeof(XDEX_DEF::METHOD_HANDLE_ITEM) * i;

        XDEX_DEF::METHOD_HANDLE_ITEM record = {};

        record.method_handle_type = _read_int16(pData + nOffset + offsetof(XDEX_DEF::METHOD_HANDLE_ITEM, method_handle_type), bIsBigEndian);
        record.field_or_method_id = _read_int16(pData + nOffset + offsetof(XDEX_DEF::METHOD_HANDLE_ITEM, field_or_method_id), bIsBigEndian);

        listResult.append(record);
    }

    return listResult;
}

QList<QString> XDEX::getStrings(QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    QList<QString> listResult;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    bool bProgressOwnerAlive = progressLifetime.isValid();
    if (!bProgressOwnerAlive) return listResult;

    bool bIsBigEndian = isBigEndian();

    XDEX_DEF::MAP_ITEM map_strings = getMapItem(XDEX_DEF::TYPE_STRING_ID_ITEM, pMapItems, pPdStruct);

    // string_ids is a table of 4-byte offsets; clamp the declared count to the file size
    quint32 nStringCount = clampTableCount(map_strings.nCount, map_strings.nOffset, sizeof(XDEX_DEF::STRING_ITEM_ID), getSize());

    QByteArray baData = read_array_process(getHeader_data_off(), getHeader_data_size(), pPdStruct);
    bProgressOwnerAlive = isPdStructLifetimeAlive(progressLifetime);
    if (!bProgressOwnerAlive) return {};

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nStringCount);

    for (quint32 i = 0; bProgressOwnerAlive && (i < nStringCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        QString sString = _getString(map_strings, i, bIsBigEndian, baData.data(), baData.size(), getHeader_data_off());

        listResult.append(sString);
        bProgressOwnerAlive = XBinary::setPdStructCurrentIncrementChecked(pPdStruct, _nFreeIndex, progressLifetime);
        if (!bProgressOwnerAlive) return {};
    }

    if (bProgressOwnerAlive) {
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }

    return listResult;
}

QString XDEX::_getString(XDEX_DEF::MAP_ITEM map_stringIdItem, quint32 nIndex, bool bIsBigEndian)
{
    QString sResult;

    if (nIndex < map_stringIdItem.nCount) {
        qint64 nOffset = map_stringIdItem.nOffset + sizeof(quint32) * nIndex;

        quint32 nStringsOffset = read_uint32(nOffset, bIsBigEndian);

        sResult = _readMUTF8String(nStringsOffset);
    }

    return sResult;
}

QString XDEX::_getString(XDEX_DEF::MAP_ITEM map_stringIdItem, quint32 nIndex, bool bIsBigEndian, char *pData, qint32 nDataSize, qint32 nDataOffset)
{
    QString sResult;

    if (nIndex < map_stringIdItem.nCount) {
        qint64 nOffset = map_stringIdItem.nOffset + sizeof(quint32) * nIndex;

        qint32 nStringsOffset = (qint32)read_uint32(nOffset, bIsBigEndian);

        sResult = _readMUTF8String(nStringsOffset, pData, nDataSize, nDataOffset);
    }

    return sResult;
}

QString XDEX::_getTypeItemtString(XDEX_DEF::MAP_ITEM map_stringIdItem, XDEX_DEF::MAP_ITEM map_typeItemId, quint32 nIndex, bool bIsBigEndian)
{
    QString sResult;

    if (nIndex < map_typeItemId.nCount) {
        quint32 nID = read_uint32(map_typeItemId.nOffset + sizeof(quint32) * nIndex, bIsBigEndian);

        sResult = _getString(map_stringIdItem, nID, bIsBigEndian);
    }

    return sResult;
}

QList<quint32> XDEX::_getTypeList(qint64 nOffset, bool bIsBigEndian, PDSTRUCT *pPdStruct)
{
    QList<quint32> listResult;

    const qint64 nFileSize = getSize();

    if ((nOffset > 0) && ((nOffset + (qint64)sizeof(quint32)) <= nFileSize)) {
        quint32 nCount = read_uint32(nOffset, bIsBigEndian);

        // Clamp to the number of 2-byte entries that can actually fit after the count word,
        // so a crafted parameters_off/type_list count cannot drive an unbounded loop/OOM.
        qint64 nMaxEntries = (nFileSize - (nOffset + (qint64)sizeof(quint32))) / (qint64)sizeof(quint16);
        if (nMaxEntries < 0) {
            nMaxEntries = 0;
        }
        if ((qint64)nCount > nMaxEntries) {
            nCount = (quint32)nMaxEntries;
        }

        for (quint32 i = 0; (i < nCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            quint32 nType = read_uint16(nOffset + sizeof(quint32) + sizeof(quint16) * i, bIsBigEndian);
            listResult.append(nType);
        }
    }

    return listResult;
}

QList<QString> XDEX::getTypeItemStrings(QList<XDEX_DEF::MAP_ITEM> *pMapItems, QList<QString> *pListStrings, PDSTRUCT *pPdStruct)
{
    QList<QString> listResult;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    bool bProgressOwnerAlive = progressLifetime.isValid();
    if (!bProgressOwnerAlive) return listResult;

    bool bIsBigEndian = isBigEndian();

    qint32 nStringsCount = pListStrings->count();

    XDEX_DEF::MAP_ITEM map_items = getMapItem(XDEX_DEF::TYPE_TYPE_ID_ITEM, pMapItems, pPdStruct);

    // type_ids is a table of 4-byte string-pool indices; clamp the declared count to the file size
    quint32 nTypeCount = clampTableCount(map_items.nCount, map_items.nOffset, sizeof(XDEX_DEF::TYPE_ITEM_ID), getSize());

    qint32 _nFreeIndex = XBinary::getFreeIndex(pPdStruct);
    XBinary::setPdStructInit(pPdStruct, _nFreeIndex, nTypeCount);

    for (quint32 i = 0; bProgressOwnerAlive && (i < nTypeCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        quint32 nOffset = map_items.nOffset + sizeof(quint32) * i;

        quint32 nItem = read_uint32(nOffset, bIsBigEndian);

        if (((qint32)nItem >= 0) && ((qint32)nItem < nStringsCount)) {
            QString sString = pListStrings->at(nItem);

            listResult.append(sString);
        }

        bProgressOwnerAlive = XBinary::setPdStructCurrentIncrementChecked(pPdStruct, _nFreeIndex, progressLifetime);
        if (!bProgressOwnerAlive) return {};
    }

    if (bProgressOwnerAlive) {
        XBinary::setPdStructFinished(pPdStruct, _nFreeIndex);
    }

    return listResult;
}

void XDEX::getProtoIdItems(QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    Q_UNUSED(pMapItems)
    Q_UNUSED(pPdStruct)
}

QString XDEX::getStringItemIdString(XDEX_DEF::STRING_ITEM_ID stringItemId)
{
    return _readMUTF8String(stringItemId.string_data_off);
}

QString XDEX::getStringItemIdString(XDEX_DEF::STRING_ITEM_ID stringItemId, char *pData, qint32 nDataSize, qint32 nDataOffset)
{
    return _readMUTF8String(stringItemId.string_data_off, pData, nDataSize, nDataOffset);
}

QString XDEX::getStringItemIdString(QList<XDEX_DEF::STRING_ITEM_ID> *pList, qint32 nIndex, char *pData, qint32 nDataSize, qint32 nDataOffset)
{
    QString sResult;

    if ((nIndex >= 0) && (nIndex < pList->count())) {
        sResult = getStringItemIdString(pList->at(nIndex), pData, nDataSize, nDataOffset);
    }

    return sResult;
}

QString XDEX::getTypeItemIdString(XDEX_DEF::TYPE_ITEM_ID typeItemId, XDEX_DEF::MAP_ITEM *pMapItemStrings)
{
    return _readMUTF8String(read_uint32(pMapItemStrings->nOffset + sizeof(quint32) * typeItemId.descriptor_idx, isBigEndian()));
}

QString XDEX::getTypeItemIdString(XDEX_DEF::TYPE_ITEM_ID typeItemId, XDEX_DEF::MAP_ITEM *pMapItemStrings, char *pData, qint32 nDataSize, qint32 nDataOffset)
{
    return _readMUTF8String(read_uint32(pMapItemStrings->nOffset + sizeof(quint32) * typeItemId.descriptor_idx, isBigEndian()), pData, nDataSize, nDataOffset);
}

QString XDEX::getTypeItemIdString(QList<XDEX_DEF::TYPE_ITEM_ID> *pList, qint32 nIndex, XDEX_DEF::MAP_ITEM *pMapItemStrings, char *pData, qint32 nDataSize,
                                  qint32 nDataOffset)
{
    QString sResult;

    if ((nIndex >= 0) && (nIndex < pList->count())) {
        sResult = getTypeItemIdString(pList->at(nIndex), pMapItemStrings, pData, nDataSize, nDataOffset);
    }

    return sResult;
}

QString XDEX::getProtoItemIdString(XDEX_DEF::PROTO_ITEM_ID protoItemId, XDEX_DEF::MAP_ITEM *pMapItemStrings, XDEX_DEF::MAP_ITEM *pMapItemTypes)
{
    QString sResult;

    if (!pMapItemStrings) {
        return sResult;
    }

    bool bIsBigEndian = isBigEndian();

    // shorty_idx indexes the string pool directly (the shorty descriptor, e.g. "VLL")
    QString sShorty = _readMUTF8String(read_uint32(pMapItemStrings->nOffset + sizeof(quint32) * protoItemId.shorty_idx, bIsBigEndian));

    // return_type_idx indexes the TYPE pool, not the string pool: type_ids[idx].descriptor_idx -> string pool
    QString sReturnType;
    if (pMapItemTypes) {
        quint32 nDescriptorIdx = read_uint32(pMapItemTypes->nOffset + sizeof(quint32) * protoItemId.return_type_idx, bIsBigEndian);
        sReturnType = _readMUTF8String(read_uint32(pMapItemStrings->nOffset + sizeof(quint32) * nDescriptorIdx, bIsBigEndian));
    }

    if (sReturnType.isEmpty()) {
        sResult = sShorty;
    } else {
        sResult = QString("%1 (%2)").arg(sReturnType, sShorty);
    }

    return sResult;
}

qint64 XDEX::_readSleb128(qint64 nOffset, qint32 nMax, qint32 *pnByteSize)
{
    qint64 nResult = 0;
    qint32 nShift = 0;
    qint32 i = 0;
    quint8 nByte = 0;

    const qint64 nFileSize = getSize();

    do {
        if ((i >= nMax) || (nOffset + i >= nFileSize) || (nShift >= 64)) {
            break;
        }

        nByte = read_uint8(nOffset + i);
        nResult |= (qint64)(nByte & 0x7F) << nShift;
        nShift += 7;
        i++;
    } while (nByte & 0x80);

    // Sign-extend from the final payload bit.
    if ((nShift < 64) && (nByte & 0x40)) {
        nResult |= -((qint64)1 << nShift);
    }

    if (pnByteSize) {
        *pnByteSize = i;
    }

    return nResult;
}

QString XDEX::_mutf8ToUnicode(const char *pData, qint32 nSize)
{
    QString sResult;

    if ((pData == nullptr) || (nSize <= 0)) {
        return sResult;
    }

    qint32 i = 0;

    while (i < nSize) {
        quint8 a = (quint8)pData[i];

        if (a == 0) {
            break;  // MUTF-8 string terminator
        } else if (a < 0x80) {
            sResult.append(QChar((ushort)a));
            i += 1;
        } else if ((a & 0xE0) == 0xC0) {
            if ((i + 1) >= nSize) break;
            quint8 b = (quint8)pData[i + 1];
            sResult.append(QChar((ushort)(((a & 0x1F) << 6) | (b & 0x3F))));  // 0xC0 0x80 -> U+0000
            i += 2;
        } else if ((a & 0xF0) == 0xE0) {
            if ((i + 2) >= nSize) break;
            quint8 b = (quint8)pData[i + 1];
            quint8 c = (quint8)pData[i + 2];
            // A CESU-8 surrogate half; consecutive halves combine into a supplementary char inside QString.
            sResult.append(QChar((ushort)(((a & 0x0F) << 12) | ((b & 0x3F) << 6) | (c & 0x3F))));
            i += 3;
        } else if ((a & 0xF8) == 0xF0) {
            // Tolerate standard 4-byte UTF-8 (not strict MUTF-8) -> UTF-16 surrogate pair.
            if ((i + 3) >= nSize) break;
            quint8 b = (quint8)pData[i + 1];
            quint8 c = (quint8)pData[i + 2];
            quint8 d = (quint8)pData[i + 3];
            quint32 nCp = (((quint32)(a & 0x07)) << 18) | (((quint32)(b & 0x3F)) << 12) | (((quint32)(c & 0x3F)) << 6) | (quint32)(d & 0x3F);
            if ((nCp >= 0x10000) && (nCp <= 0x10FFFF)) {
                nCp -= 0x10000;
                sResult.append(QChar((ushort)(0xD800 + (nCp >> 10))));
                sResult.append(QChar((ushort)(0xDC00 + (nCp & 0x3FF))));
            }
            i += 4;
        } else {
            i += 1;  // invalid lead byte
        }
    }

    return sResult;
}

QString XDEX::_readMUTF8String(const char *pData, qint32 nMaxSize)
{
    if ((pData == nullptr) || (nMaxSize <= 0)) {
        return QString();
    }

    PACKED_UINT ulebSize = _read_uleb128(pData, nMaxSize);

    if (!ulebSize.bIsValid) {
        return QString();
    }

    return _mutf8ToUnicode(pData + ulebSize.nByteSize, nMaxSize - ulebSize.nByteSize);
}

QString XDEX::_readMUTF8String(qint64 nOffset, char *pData, qint32 nDataSize, qint32 nDataOffset)
{
    QString sResult;

    if ((nOffset >= nDataOffset) && (nOffset < (qint64)nDataOffset + nDataSize)) {
        char *pStringData = pData + (nOffset - nDataOffset);
        qint32 nStringSize = nDataSize - (qint32)(nOffset - nDataOffset);
        sResult = _readMUTF8String(pStringData, nStringSize);
    }

    return sResult;
}

QString XDEX::_readMUTF8String(qint64 nOffset)
{
    QString sResult;

    const qint64 nFileSize = getSize();

    if ((nOffset < 0) || (nOffset >= nFileSize)) {
        return sResult;
    }

    PACKED_UINT ulebSize = read_uleb128(nOffset, 5);

    if (!ulebSize.bIsValid) {
        return sResult;
    }

    qint64 nDataStart = nOffset + ulebSize.nByteSize;
    qint64 nAvail = nFileSize - nDataStart;

    if (nAvail <= 0) {
        return sResult;
    }

    // Each UTF-16 unit is at most 3 MUTF-8 bytes; +1 for the terminator.
    qint64 nMax = qMin<qint64>((qint64)ulebSize.nValue * 3 + 1, nAvail);

    QByteArray baData = read_array(nDataStart, nMax);
    sResult = _mutf8ToUnicode(baData.constData(), (qint32)baData.size());

    return sResult;
}

XDEX::CLASS_DATA XDEX::getClassData(qint64 nOffset, PDSTRUCT *pPdStruct)
{
    CLASS_DATA result = {};

    if (nOffset <= 0) {
        return result;
    }

    const qint64 nFileSize = getSize();
    qint64 nCurrent = nOffset;
    PACKED_UINT u;

    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;
    result.static_fields_size = (quint32)u.nValue;
    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;
    result.instance_fields_size = (quint32)u.nValue;
    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;
    result.direct_methods_size = (quint32)u.nValue;
    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;
    result.virtual_methods_size = (quint32)u.nValue;

    quint32 nIdx = 0;
    for (quint32 i = 0; (i < result.static_fields_size) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XDEX_DEF::ENCODED_FIELD record = {};
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        nIdx += (quint32)u.nValue;
        record.field_idx = nIdx;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        record.access_flags = (quint32)u.nValue;
        result.listStaticFields.append(record);
    }

    nIdx = 0;
    for (quint32 i = 0; (i < result.instance_fields_size) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XDEX_DEF::ENCODED_FIELD record = {};
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        nIdx += (quint32)u.nValue;
        record.field_idx = nIdx;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        record.access_flags = (quint32)u.nValue;
        result.listInstanceFields.append(record);
    }

    nIdx = 0;
    for (quint32 i = 0; (i < result.direct_methods_size) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XDEX_DEF::ENCODED_METHOD record = {};
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        nIdx += (quint32)u.nValue;
        record.method_idx = nIdx;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        record.access_flags = (quint32)u.nValue;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        record.code_off = (quint32)u.nValue;
        result.listDirectMethods.append(record);
    }

    nIdx = 0;
    for (quint32 i = 0; (i < result.virtual_methods_size) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        XDEX_DEF::ENCODED_METHOD record = {};
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        nIdx += (quint32)u.nValue;
        record.method_idx = nIdx;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        record.access_flags = (quint32)u.nValue;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        record.code_off = (quint32)u.nValue;
        result.listVirtualMethods.append(record);
    }

    return result;
}

qint64 XDEX::getClassDataItemSize(qint64 nOffset, PDSTRUCT *pPdStruct)
{
    if (nOffset <= 0) {
        return 0;
    }

    const qint64 nFileSize = getSize();
    qint64 nCurrent = nOffset;
    PACKED_UINT u;

    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;
    quint32 nStaticFields = (quint32)u.nValue;
    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;
    quint32 nInstanceFields = (quint32)u.nValue;
    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;
    quint32 nDirectMethods = (quint32)u.nValue;
    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;
    quint32 nVirtualMethods = (quint32)u.nValue;

    quint64 nFieldEntries = (quint64)nStaticFields + nInstanceFields;  // 2 uleb each
    for (quint64 i = 0; (i < nFieldEntries) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
    }

    quint64 nMethodEntries = (quint64)nDirectMethods + nVirtualMethods;  // 3 uleb each
    for (quint64 i = 0; (i < nMethodEntries) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;
    }

    return nCurrent - nOffset;
}

XDEX_DEF::CODE_ITEM XDEX::readCodeItem(qint64 nOffset)
{
    XDEX_DEF::CODE_ITEM result = {};

    bool bIsBigEndian = isBigEndian();

    result.registers_size = read_uint16(nOffset + offsetof(XDEX_DEF::CODE_ITEM, registers_size), bIsBigEndian);
    result.ins_size = read_uint16(nOffset + offsetof(XDEX_DEF::CODE_ITEM, ins_size), bIsBigEndian);
    result.outs_size = read_uint16(nOffset + offsetof(XDEX_DEF::CODE_ITEM, outs_size), bIsBigEndian);
    result.tries_size = read_uint16(nOffset + offsetof(XDEX_DEF::CODE_ITEM, tries_size), bIsBigEndian);
    result.debug_info_off = read_uint32(nOffset + offsetof(XDEX_DEF::CODE_ITEM, debug_info_off), bIsBigEndian);
    result.insns_size = read_uint32(nOffset + offsetof(XDEX_DEF::CODE_ITEM, insns_size), bIsBigEndian);

    return result;
}

qint64 XDEX::getCodeItemSize(qint64 nOffset, PDSTRUCT *pPdStruct)
{
    const qint64 nFileSize = getSize();
    bool bIsBigEndian = isBigEndian();

    quint16 nTriesSize = read_uint16(nOffset + offsetof(XDEX_DEF::CODE_ITEM, tries_size), bIsBigEndian);
    quint32 nInsnsSize = read_uint32(nOffset + offsetof(XDEX_DEF::CODE_ITEM, insns_size), bIsBigEndian);

    qint64 nCurrent = nOffset + (qint64)sizeof(XDEX_DEF::CODE_ITEM) + (qint64)nInsnsSize * sizeof(quint16);

    if (nTriesSize != 0) {
        if (nInsnsSize & 1) {
            nCurrent += sizeof(quint16);  // padding so tries[] is 4-byte aligned
        }

        nCurrent += (qint64)nTriesSize * sizeof(XDEX_DEF::TRY_ITEM);  // try_item[]

        // encoded_catch_handler_list: uleb size + handlers
        PACKED_UINT handlersCount = read_uleb128(nCurrent, 5);
        nCurrent += handlersCount.nByteSize;

        for (quint64 h = 0; (h < handlersCount.nValue) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); h++) {
            qint32 nSlebBytes = 0;
            qint64 nHandlerSize = _readSleb128(nCurrent, 5, &nSlebBytes);
            nCurrent += nSlebBytes;

            qint64 nPairs = (nHandlerSize < 0) ? -nHandlerSize : nHandlerSize;

            for (qint64 p = 0; (p < nPairs) && (nCurrent < nFileSize); p++) {
                PACKED_UINT tIdx = read_uleb128(nCurrent, 5);
                nCurrent += tIdx.nByteSize;
                PACKED_UINT addr = read_uleb128(nCurrent, 5);
                nCurrent += addr.nByteSize;
            }

            if (nHandlerSize <= 0) {  // has a catch-all address
                PACKED_UINT catchAll = read_uleb128(nCurrent, 5);
                nCurrent += catchAll.nByteSize;
            }
        }
    }

    return nCurrent - nOffset;
}

qint64 XDEX::getStringDataItemSize(qint64 nOffset)
{
    const qint64 nFileSize = getSize();

    if ((nOffset < 0) || (nOffset >= nFileSize)) {
        return 0;
    }

    PACKED_UINT ulebSize = read_uleb128(nOffset, 5);
    if (!ulebSize.bIsValid) {
        return 0;
    }

    qint64 nCurrent = nOffset + ulebSize.nByteSize;

    // MUTF-8 payload is terminated by a 0x00 byte.
    while (nCurrent < nFileSize) {
        quint8 nByte = read_uint8(nCurrent);
        nCurrent += 1;
        if (nByte == 0) {
            break;
        }
    }

    return nCurrent - nOffset;
}

qint64 XDEX::getDebugInfoItemSize(qint64 nOffset, PDSTRUCT *pPdStruct)
{
    const qint64 nFileSize = getSize();
    qint64 nCurrent = nOffset;
    PACKED_UINT u;

    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;  // line_start
    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;  // parameters_size
    quint64 nParams = u.nValue;

    for (quint64 i = 0; (i < nParams) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        u = read_uleb128(nCurrent, 5);  // parameter name (uleb128p1)
        nCurrent += u.nByteSize;
    }

    while ((nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct)) {
        quint8 nOpcode = read_uint8(nCurrent);
        nCurrent += 1;

        if (nOpcode == 0x00) {  // DBG_END_SEQUENCE
            break;
        } else if (nOpcode == 0x01) {  // DBG_ADVANCE_PC: 1 uleb
            u = read_uleb128(nCurrent, 5);
            nCurrent += u.nByteSize;
        } else if (nOpcode == 0x02) {  // DBG_ADVANCE_LINE: 1 sleb
            qint32 nSlebBytes = 0;
            _readSleb128(nCurrent, 5, &nSlebBytes);
            nCurrent += nSlebBytes;
        } else if (nOpcode == 0x03) {  // DBG_START_LOCAL: 3 uleb
            for (qint32 k = 0; k < 3; k++) {
                u = read_uleb128(nCurrent, 5);
                nCurrent += u.nByteSize;
            }
        } else if (nOpcode == 0x04) {  // DBG_START_LOCAL_EXTENDED: 4 uleb
            for (qint32 k = 0; k < 4; k++) {
                u = read_uleb128(nCurrent, 5);
                nCurrent += u.nByteSize;
            }
        } else if ((nOpcode == 0x05) || (nOpcode == 0x06) || (nOpcode == 0x09)) {  // END_LOCAL / RESTART_LOCAL / SET_FILE: 1 uleb
            u = read_uleb128(nCurrent, 5);
            nCurrent += u.nByteSize;
        }
        // 0x07 SET_PROLOGUE_END, 0x08 SET_EPILOGUE_BEGIN and special opcodes 0x0A..0xFF take no arguments
    }

    return nCurrent - nOffset;
}

qint64 XDEX::getEncodedValueSize(qint64 nOffset, PDSTRUCT *pPdStruct, qint32 nDepth)
{
    const qint64 nFileSize = getSize();

    if ((nOffset < 0) || (nOffset >= nFileSize)) {
        return 0;
    }

    const qint32 nMaxDepth = 256;
    if (nDepth > nMaxDepth) {
        return 1;  // stop recursing on pathologically nested input (still consume the type byte)
    }

    quint8 nHeader = read_uint8(nOffset);
    qint32 nValueType = nHeader & 0x1F;
    qint32 nValueArg = (nHeader >> 5) & 0x7;

    qint64 nPayload = 0;

    if (nValueType == 0x1C) {  // VALUE_ARRAY
        nPayload = getEncodedArrayItemSize(nOffset + 1, pPdStruct, nDepth + 1);
    } else if (nValueType == 0x1D) {  // VALUE_ANNOTATION
        nPayload = getEncodedAnnotationSize(nOffset + 1, pPdStruct, nDepth + 1);
    } else if ((nValueType == 0x1E) || (nValueType == 0x1F)) {  // VALUE_NULL / VALUE_BOOLEAN (no payload)
        nPayload = 0;
    } else {
        nPayload = nValueArg + 1;  // fixed-width payload = (value_arg + 1) bytes
    }

    return 1 + nPayload;
}

qint64 XDEX::getEncodedArrayItemSize(qint64 nOffset, PDSTRUCT *pPdStruct, qint32 nDepth)
{
    const qint64 nFileSize = getSize();
    qint64 nCurrent = nOffset;

    PACKED_UINT nSize = read_uleb128(nCurrent, 5);
    nCurrent += nSize.nByteSize;

    for (quint64 i = 0; (i < nSize.nValue) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nValueSize = getEncodedValueSize(nCurrent, pPdStruct, nDepth + 1);
        if (nValueSize <= 0) {
            break;
        }
        nCurrent += nValueSize;
    }

    return nCurrent - nOffset;
}

qint64 XDEX::getEncodedAnnotationSize(qint64 nOffset, PDSTRUCT *pPdStruct, qint32 nDepth)
{
    const qint64 nFileSize = getSize();
    qint64 nCurrent = nOffset;
    PACKED_UINT u;

    u = read_uleb128(nCurrent, 5);
    nCurrent += u.nByteSize;  // type_idx
    PACKED_UINT nSize = read_uleb128(nCurrent, 5);
    nCurrent += nSize.nByteSize;  // size

    for (quint64 i = 0; (i < nSize.nValue) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        u = read_uleb128(nCurrent, 5);
        nCurrent += u.nByteSize;  // name_idx
        qint64 nValueSize = getEncodedValueSize(nCurrent, pPdStruct, nDepth + 1);
        if (nValueSize <= 0) {
            break;
        }
        nCurrent += nValueSize;
    }

    return nCurrent - nOffset;
}

qint64 XDEX::getAnnotationItemSize(qint64 nOffset, PDSTRUCT *pPdStruct)
{
    // visibility (1 byte) + encoded_annotation
    return 1 + getEncodedAnnotationSize(nOffset + 1, pPdStruct, 0);
}

qint64 XDEX::getAnnotationsDirectoryItemSize(qint64 nOffset)
{
    bool bIsBigEndian = isBigEndian();

    // uint class_annotations_off; uint fields_size; uint annotated_methods_size; uint annotated_parameters_size;
    // then 8-byte entries: field_annotation[], method_annotation[], parameter_annotation[]
    quint32 nFieldsSize = read_uint32(nOffset + 4, bIsBigEndian);
    quint32 nMethodsSize = read_uint32(nOffset + 8, bIsBigEndian);
    quint32 nParamsSize = read_uint32(nOffset + 12, bIsBigEndian);

    return 16 + (((qint64)nFieldsSize + nMethodsSize + nParamsSize) * 8);
}

QList<quint32> XDEX::getProtoParameterTypes(quint32 nProtoIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    QList<quint32> listResult;

    bool bIsBigEndian = isBigEndian();

    XDEX_DEF::MAP_ITEM mapProto = getMapItem(XDEX_DEF::TYPE_PROTO_ID_ITEM, pMapItems, pPdStruct);

    if ((mapProto.nOffset == 0) || (nProtoIndex >= mapProto.nCount)) {
        return listResult;
    }

    qint64 nProtoOffset = mapProto.nOffset + (qint64)nProtoIndex * sizeof(XDEX_DEF::PROTO_ITEM_ID);
    quint32 nParametersOff = read_uint32(nProtoOffset + offsetof(XDEX_DEF::PROTO_ITEM_ID, parameters_off), bIsBigEndian);

    if (nParametersOff != 0) {
        listResult = _getTypeList(nParametersOff, bIsBigEndian, pPdStruct);
    }

    return listResult;
}

QString XDEX::getAccessFlagsString(quint32 nAccessFlags)
{
    QStringList listParts;

    if (nAccessFlags & XDEX_DEF::ACC_PUBLIC) listParts.append("public");
    if (nAccessFlags & XDEX_DEF::ACC_PRIVATE) listParts.append("private");
    if (nAccessFlags & XDEX_DEF::ACC_PROTECTED) listParts.append("protected");
    if (nAccessFlags & XDEX_DEF::ACC_STATIC) listParts.append("static");
    if (nAccessFlags & XDEX_DEF::ACC_FINAL) listParts.append("final");
    if (nAccessFlags & XDEX_DEF::ACC_SYNCHRONIZED) listParts.append("synchronized");
    if (nAccessFlags & XDEX_DEF::ACC_VOLATILE) listParts.append("volatile");
    if (nAccessFlags & XDEX_DEF::ACC_TRANSIENT) listParts.append("transient");
    if (nAccessFlags & XDEX_DEF::ACC_NATIVE) listParts.append("native");
    if (nAccessFlags & XDEX_DEF::ACC_INTERFACE) listParts.append("interface");
    if (nAccessFlags & XDEX_DEF::ACC_ABSTRACT) listParts.append("abstract");
    if (nAccessFlags & XDEX_DEF::ACC_STRICT) listParts.append("strictfp");
    if (nAccessFlags & XDEX_DEF::ACC_SYNTHETIC) listParts.append("synthetic");
    if (nAccessFlags & XDEX_DEF::ACC_ANNOTATION) listParts.append("annotation");
    if (nAccessFlags & XDEX_DEF::ACC_ENUM) listParts.append("enum");
    if (nAccessFlags & XDEX_DEF::ACC_CONSTRUCTOR) listParts.append("constructor");
    if (nAccessFlags & XDEX_DEF::ACC_DECLARED_SYNCHRONIZED) listParts.append("declared-synchronized");

    return listParts.join(" ");
}

QString XDEX::descriptorToString(const QString &sDescriptor)
{
    if (sDescriptor.isEmpty()) {
        return QString();
    }

    qint32 nArrayDepth = 0;
    qint32 i = 0;
    while ((i < sDescriptor.size()) && (sDescriptor.at(i) == QChar('['))) {
        nArrayDepth++;
        i++;
    }

    QString sBase;

    if (i < sDescriptor.size()) {
        QChar c = sDescriptor.at(i);

        if (c == QChar('V')) sBase = "void";
        else if (c == QChar('Z')) sBase = "boolean";
        else if (c == QChar('B')) sBase = "byte";
        else if (c == QChar('S')) sBase = "short";
        else if (c == QChar('C')) sBase = "char";
        else if (c == QChar('I')) sBase = "int";
        else if (c == QChar('J')) sBase = "long";
        else if (c == QChar('F')) sBase = "float";
        else if (c == QChar('D')) sBase = "double";
        else if (c == QChar('L')) {
            qint32 nEnd = sDescriptor.indexOf(QChar(';'), i);
            QString sClass = (nEnd > i) ? sDescriptor.mid(i + 1, nEnd - i - 1) : sDescriptor.mid(i + 1);
            sClass.replace(QChar('/'), QChar('.'));
            sBase = sClass;
        } else {
            sBase = sDescriptor.mid(i);  // unknown, pass through
        }
    }

    for (qint32 k = 0; k < nArrayDepth; k++) {
        sBase += "[]";
    }

    return sBase;
}

QString XDEX::_typeIndexToDescriptor(quint32 nTypeIndex, XDEX_DEF::MAP_ITEM *pMapStrings, XDEX_DEF::MAP_ITEM *pMapTypes)
{
    if ((pMapTypes->nOffset == 0) || (nTypeIndex >= pMapTypes->nCount)) {
        return QString();
    }

    bool bIsBigEndian = isBigEndian();

    quint32 nDescriptorIdx = read_uint32(pMapTypes->nOffset + (qint64)nTypeIndex * sizeof(quint32), bIsBigEndian);

    if ((pMapStrings->nOffset == 0) || (nDescriptorIdx >= pMapStrings->nCount)) {
        return QString();
    }

    quint32 nStringDataOff = read_uint32(pMapStrings->nOffset + (qint64)nDescriptorIdx * sizeof(quint32), bIsBigEndian);

    return _readMUTF8String(nStringDataOff);
}

QString XDEX::getClassString(quint32 nTypeIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    XDEX_DEF::MAP_ITEM mapStrings = getMapItem(XDEX_DEF::TYPE_STRING_ID_ITEM, pMapItems, pPdStruct);
    XDEX_DEF::MAP_ITEM mapTypes = getMapItem(XDEX_DEF::TYPE_TYPE_ID_ITEM, pMapItems, pPdStruct);

    return descriptorToString(_typeIndexToDescriptor(nTypeIndex, &mapStrings, &mapTypes));
}

QString XDEX::getProtoString(quint32 nProtoIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    QString sResult;

    bool bIsBigEndian = isBigEndian();

    XDEX_DEF::MAP_ITEM mapStrings = getMapItem(XDEX_DEF::TYPE_STRING_ID_ITEM, pMapItems, pPdStruct);
    XDEX_DEF::MAP_ITEM mapTypes = getMapItem(XDEX_DEF::TYPE_TYPE_ID_ITEM, pMapItems, pPdStruct);
    XDEX_DEF::MAP_ITEM mapProto = getMapItem(XDEX_DEF::TYPE_PROTO_ID_ITEM, pMapItems, pPdStruct);

    if ((mapProto.nOffset == 0) || (nProtoIndex >= mapProto.nCount)) {
        return sResult;
    }

    qint64 nProtoOffset = mapProto.nOffset + (qint64)nProtoIndex * sizeof(XDEX_DEF::PROTO_ITEM_ID);
    quint32 nReturnTypeIdx = read_uint32(nProtoOffset + offsetof(XDEX_DEF::PROTO_ITEM_ID, return_type_idx), bIsBigEndian);

    QString sReturn = descriptorToString(_typeIndexToDescriptor(nReturnTypeIdx, &mapStrings, &mapTypes));

    QList<quint32> listParams = getProtoParameterTypes(nProtoIndex, pMapItems, pPdStruct);
    QStringList listParamStrings;
    for (qint32 i = 0; i < listParams.size(); i++) {
        listParamStrings.append(descriptorToString(_typeIndexToDescriptor(listParams.at(i), &mapStrings, &mapTypes)));
    }

    sResult = QString("(%1)%2").arg(listParamStrings.join(", "), sReturn);

    return sResult;
}

QString XDEX::getMethodString(quint32 nMethodIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    QString sResult;

    bool bIsBigEndian = isBigEndian();

    XDEX_DEF::MAP_ITEM mapStrings = getMapItem(XDEX_DEF::TYPE_STRING_ID_ITEM, pMapItems, pPdStruct);
    XDEX_DEF::MAP_ITEM mapTypes = getMapItem(XDEX_DEF::TYPE_TYPE_ID_ITEM, pMapItems, pPdStruct);
    XDEX_DEF::MAP_ITEM mapMethod = getMapItem(XDEX_DEF::TYPE_METHOD_ID_ITEM, pMapItems, pPdStruct);

    if ((mapMethod.nOffset == 0) || (nMethodIndex >= mapMethod.nCount)) {
        return sResult;
    }

    qint64 nMethodOffset = mapMethod.nOffset + (qint64)nMethodIndex * sizeof(XDEX_DEF::METHOD_ITEM_ID);
    quint16 nClassIdx = read_uint16(nMethodOffset + offsetof(XDEX_DEF::METHOD_ITEM_ID, class_idx), bIsBigEndian);
    quint16 nProtoIdx = read_uint16(nMethodOffset + offsetof(XDEX_DEF::METHOD_ITEM_ID, proto_idx), bIsBigEndian);
    quint32 nNameIdx = read_uint32(nMethodOffset + offsetof(XDEX_DEF::METHOD_ITEM_ID, name_idx), bIsBigEndian);

    QString sClass = descriptorToString(_typeIndexToDescriptor(nClassIdx, &mapStrings, &mapTypes));

    QString sName;
    if (nNameIdx < mapStrings.nCount) {
        sName = _readMUTF8String(read_uint32(mapStrings.nOffset + (qint64)nNameIdx * sizeof(quint32), bIsBigEndian));
    }

    QString sProto = getProtoString(nProtoIdx, pMapItems, pPdStruct);

    sResult = QString("%1.%2%3").arg(sClass, sName, sProto);

    return sResult;
}

QString XDEX::getFieldString(quint32 nFieldIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    QString sResult;

    bool bIsBigEndian = isBigEndian();

    XDEX_DEF::MAP_ITEM mapStrings = getMapItem(XDEX_DEF::TYPE_STRING_ID_ITEM, pMapItems, pPdStruct);
    XDEX_DEF::MAP_ITEM mapTypes = getMapItem(XDEX_DEF::TYPE_TYPE_ID_ITEM, pMapItems, pPdStruct);
    XDEX_DEF::MAP_ITEM mapField = getMapItem(XDEX_DEF::TYPE_FIELD_ID_ITEM, pMapItems, pPdStruct);

    if ((mapField.nOffset == 0) || (nFieldIndex >= mapField.nCount)) {
        return sResult;
    }

    qint64 nFieldOffset = mapField.nOffset + (qint64)nFieldIndex * sizeof(XDEX_DEF::FIELD_ITEM_ID);
    quint16 nClassIdx = read_uint16(nFieldOffset + offsetof(XDEX_DEF::FIELD_ITEM_ID, class_idx), bIsBigEndian);
    quint16 nTypeIdx = read_uint16(nFieldOffset + offsetof(XDEX_DEF::FIELD_ITEM_ID, type_idx), bIsBigEndian);
    quint32 nNameIdx = read_uint32(nFieldOffset + offsetof(XDEX_DEF::FIELD_ITEM_ID, name_idx), bIsBigEndian);

    QString sClass = descriptorToString(_typeIndexToDescriptor(nClassIdx, &mapStrings, &mapTypes));
    QString sType = descriptorToString(_typeIndexToDescriptor(nTypeIdx, &mapStrings, &mapTypes));

    QString sName;
    if (nNameIdx < mapStrings.nCount) {
        sName = _readMUTF8String(read_uint32(mapStrings.nOffset + (qint64)nNameIdx * sizeof(quint32), bIsBigEndian));
    }

    sResult = QString("%1.%2:%3").arg(sClass, sName, sType);

    return sResult;
}

qint64 XDEX::readEncodedValue(qint64 nOffset, ENCODED_VALUE *pValue, PDSTRUCT *pPdStruct, qint32 nDepth)
{
    ENCODED_VALUE value = {};
    value.nNestedOffset = -1;

    const qint64 nFileSize = getSize();

    if ((nOffset < 0) || (nOffset >= nFileSize)) {
        if (pValue) *pValue = value;
        return 0;
    }

    quint8 nHeader = read_uint8(nOffset);
    value.nValueType = nHeader & 0x1F;
    value.nValueArg = (nHeader >> 5) & 0x7;

    qint64 nConsumed = 1;

    if (value.nValueType == 0x1C) {  // VALUE_ARRAY
        value.nNestedOffset = nOffset + 1;
        nConsumed += getEncodedArrayItemSize(nOffset + 1, pPdStruct, nDepth + 1);
    } else if (value.nValueType == 0x1D) {  // VALUE_ANNOTATION
        value.nNestedOffset = nOffset + 1;
        nConsumed += getEncodedAnnotationSize(nOffset + 1, pPdStruct, nDepth + 1);
    } else if (value.nValueType == 0x1E) {  // VALUE_NULL (no payload)
        // nothing
    } else if (value.nValueType == 0x1F) {  // VALUE_BOOLEAN (value in arg)
        value.nValueRaw = (value.nValueArg != 0) ? 1 : 0;
    } else {
        qint32 nBytes = value.nValueArg + 1;
        quint64 nRaw = 0;
        for (qint32 i = 0; (i < nBytes) && ((nOffset + 1 + i) < nFileSize); i++) {
            nRaw |= (quint64)read_uint8(nOffset + 1 + i) << (8 * i);
        }
        value.nValueRaw = nRaw;
        nConsumed += nBytes;
    }

    value.nSize = nConsumed;

    if (pValue) *pValue = value;

    return nConsumed;
}

QList<XDEX::ENCODED_VALUE> XDEX::readEncodedArray(qint64 nOffset, PDSTRUCT *pPdStruct)
{
    QList<ENCODED_VALUE> listResult;

    const qint64 nFileSize = getSize();

    if ((nOffset <= 0) || (nOffset >= nFileSize)) {
        return listResult;
    }

    qint64 nCurrent = nOffset;
    PACKED_UINT nSize = read_uleb128(nCurrent, 5);
    nCurrent += nSize.nByteSize;

    for (quint64 i = 0; (i < nSize.nValue) && (nCurrent < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        ENCODED_VALUE value = {};
        qint64 nConsumed = readEncodedValue(nCurrent, &value, pPdStruct, 0);
        if (nConsumed <= 0) {
            break;
        }
        listResult.append(value);
        nCurrent += nConsumed;
    }

    return listResult;
}

QString XDEX::encodedValueToString(const ENCODED_VALUE &encodedValue)
{
    qint32 nBytes = encodedValue.nValueArg + 1;
    quint64 nRaw = encodedValue.nValueRaw;

    switch (encodedValue.nValueType) {
        case 0x00: return QString::number((qint64)signExtendLE(nRaw, 1));       // BYTE
        case 0x02: return QString::number((qint64)signExtendLE(nRaw, nBytes));  // SHORT
        case 0x03: return QString::number(nRaw);                                // CHAR (unsigned code unit)
        case 0x04: return QString::number((qint64)signExtendLE(nRaw, nBytes));  // INT
        case 0x06: return QString::number((qint64)signExtendLE(nRaw, nBytes));  // LONG
        case 0x10: {                                                            // FLOAT (bytes are the most-significant bytes, zero-extended to the right)
            qint32 nFloatBytes = qBound(1, nBytes, 4);                          // a crafted value_arg can exceed 4; clamp to avoid a negative shift (UB)
            quint32 nBits = (quint32)(nRaw << (8 * (4 - nFloatBytes)));
            float fValue = 0.0f;
            memcpy(&fValue, &nBits, sizeof(fValue));
            return QString::number((double)fValue);
        }
        case 0x11: {  // DOUBLE
            qint32 nDoubleBytes = qBound(1, nBytes, 8);
            quint64 nBits = nRaw << (8 * (8 - nDoubleBytes));
            double dValue = 0.0;
            memcpy(&dValue, &nBits, sizeof(dValue));
            return QString::number(dValue);
        }
        case 0x15: return QString("proto@%1").arg(nRaw);                                   // METHOD_TYPE
        case 0x16: return QString("methodhandle@%1").arg(nRaw);                            // METHOD_HANDLE
        case 0x17: return QString("string@%1").arg(nRaw);                                  // STRING
        case 0x18: return QString("type@%1").arg(nRaw);                                    // TYPE
        case 0x19: return QString("field@%1").arg(nRaw);                                   // FIELD
        case 0x1A: return QString("method@%1").arg(nRaw);                                  // METHOD
        case 0x1B: return QString("enum@%1").arg(nRaw);                                    // ENUM
        case 0x1C: return QStringLiteral("{...}");                                         // ARRAY
        case 0x1D: return QStringLiteral("@annotation");                                   // ANNOTATION
        case 0x1E: return QStringLiteral("null");                                          // NULL
        case 0x1F: return (nRaw != 0) ? QStringLiteral("true") : QStringLiteral("false");  // BOOLEAN
    }

    return QString();
}

QMap<quint64, QString> XDEX::getHeaderMagics()
{
    return XBinary::XIDSTRING_createMap(_TABLE_XDEX_HeaderMagics, sizeof(_TABLE_XDEX_HeaderMagics) / sizeof(XBinary::XIDSTRING));
}

QMap<quint64, QString> XDEX::getHeaderVersions()
{
    return XBinary::XIDSTRING_createMap(_TABLE_XDEX_HeaderVersions, sizeof(_TABLE_XDEX_HeaderVersions) / sizeof(XBinary::XIDSTRING));
}

QMap<quint64, QString> XDEX::getHeaderEndianTags()
{
    return XBinary::XIDSTRING_createMap(_TABLE_XDEX_HeaderEndianTags, sizeof(_TABLE_XDEX_HeaderEndianTags) / sizeof(XBinary::XIDSTRING));
}

bool XDEX::isStringPoolSorted(QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct)
{
    bool bResult = true;

    bool bIsBigEndian = isBigEndian();

    XDEX_DEF::MAP_ITEM map_strings = getMapItem(XDEX_DEF::TYPE_STRING_ID_ITEM, pMapItems, pPdStruct);

    quint32 nStringCount = clampTableCount(map_strings.nCount, map_strings.nOffset, sizeof(XDEX_DEF::STRING_ITEM_ID), getSize());

    qint32 nPrevStringOffset = 0;

    for (quint32 i = 0; (i < nStringCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        qint64 nOffset = map_strings.nOffset + sizeof(quint32) * i;

        qint32 nStringOffset = (qint32)read_uint32(nOffset, bIsBigEndian);

        if (nStringOffset < nPrevStringOffset) {
            bResult = false;

            break;
        }

        nPrevStringOffset = nStringOffset;
    }

    return bResult;
}

bool XDEX::_hasUnicodeNameInList(const QList<quint32> &nameIndices, QList<QString> *pListStrings, PDSTRUCT *pPdStruct) const
{
    const qint32 nNumberOfStrings = pListStrings->count();
    const qint32 nCount = nameIndices.count();

    for (qint32 i = 0; (i < nCount) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
        if (XBinary::isStringUnicode(getStringByIndex(pListStrings, nameIndices.at(i), nNumberOfStrings))) {
            return true;
        }
    }

    return false;
}

bool XDEX::isFieldNamesUnicode(QList<XDEX_DEF::FIELD_ITEM_ID> *pListIDs, QList<QString> *pListStrings, PDSTRUCT *pPdStruct)
{
    QList<quint32> nameIndices;
    nameIndices.reserve(pListIDs->count());
    for (const XDEX_DEF::FIELD_ITEM_ID &id : *pListIDs) nameIndices.append(id.name_idx);
    return _hasUnicodeNameInList(nameIndices, pListStrings, pPdStruct);
}

bool XDEX::isMethodNamesUnicode(QList<XDEX_DEF::METHOD_ITEM_ID> *pListIDs, QList<QString> *pListStrings, PDSTRUCT *pPdStruct)
{
    QList<quint32> nameIndices;
    nameIndices.reserve(pListIDs->count());
    for (const XDEX_DEF::METHOD_ITEM_ID &id : *pListIDs) nameIndices.append(id.name_idx);
    return _hasUnicodeNameInList(nameIndices, pListStrings, pPdStruct);
}

qint64 XDEX::getDataSizeByType(qint32 nType, qint64 nOffset, qint32 nCount, bool bIsBigEndian, PDSTRUCT *pPdStruct)
{
    qint64 nResult = 0;

    const qint64 nFileSize = getSize();

    if (nType == XDEX_DEF::TYPE_HEADER_ITEM) {
        nResult = sizeof(XDEX_DEF::HEADER);
    } else if ((nType == XDEX_DEF::TYPE_STRING_ID_ITEM) || (nType == XDEX_DEF::TYPE_TYPE_ID_ITEM) || (nType == XDEX_DEF::TYPE_CALL_SITE_ID_ITEM)) {
        nResult = nCount * sizeof(quint32);
    } else if (nType == XDEX_DEF::TYPE_PROTO_ID_ITEM) {
        nResult = nCount * sizeof(XDEX_DEF::PROTO_ITEM_ID);
    } else if ((nType == XDEX_DEF::TYPE_FIELD_ID_ITEM) || (nType == XDEX_DEF::TYPE_METHOD_ID_ITEM) || (nType == XDEX_DEF::TYPE_METHOD_HANDLE_ITEM)) {
        nResult = nCount * sizeof(XDEX_DEF::FIELD_ITEM_ID);
    } else if (nType == XDEX_DEF::TYPE_CLASS_DEF_ITEM) {
        nResult = nCount * sizeof(XDEX_DEF::CLASS_ITEM_DEF);
    } else if (nType == XDEX_DEF::TYPE_MAP_LIST) {
        nCount = read_uint32(nOffset, bIsBigEndian);
        nResult = sizeof(quint32) + (nCount * sizeof(XDEX_DEF::MAP_ITEM));
    } else if (nType == XDEX_DEF::TYPE_TYPE_LIST) {
        qint64 nCurrentOffset = nOffset;

        // Each list consumes at least a 4-byte size prefix, so the file bounds the iteration count.
        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            quint32 nListCount = read_uint32(nCurrentOffset, bIsBigEndian);
            nCurrentOffset += sizeof(quint32) + (qint64)nListCount * sizeof(quint16);

            // type_list items are 4-byte aligned
            if (nCurrentOffset % 4) {
                nCurrentOffset += 2;
            }
        }

        nResult = nCurrentOffset - nOffset;
    } else if ((nType == XDEX_DEF::TYPE_ANNOTATION_SET_REF_LIST) || (nType == XDEX_DEF::TYPE_ANNOTATION_SET_ITEM)) {
        qint64 nCurrentOffset = nOffset;

        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            quint32 nListCount = read_uint32(nCurrentOffset, bIsBigEndian);
            nCurrentOffset += sizeof(quint32) + (qint64)nListCount * sizeof(quint32);
        }

        nResult = nCurrentOffset - nOffset;
    } else if (nType == XDEX_DEF::TYPE_STRING_DATA_ITEM) {
        qint64 nCurrentOffset = nOffset;
        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            qint64 nItemSize = getStringDataItemSize(nCurrentOffset);
            if (nItemSize <= 0) break;
            nCurrentOffset += nItemSize;
        }
        nResult = nCurrentOffset - nOffset;
    } else if (nType == XDEX_DEF::TYPE_DEBUG_INFO_ITEM) {
        qint64 nCurrentOffset = nOffset;
        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            qint64 nItemSize = getDebugInfoItemSize(nCurrentOffset, pPdStruct);
            if (nItemSize <= 0) break;
            nCurrentOffset += nItemSize;
        }
        nResult = nCurrentOffset - nOffset;
    } else if (nType == XDEX_DEF::TYPE_CLASS_DATA_ITEM) {
        qint64 nCurrentOffset = nOffset;
        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            qint64 nItemSize = getClassDataItemSize(nCurrentOffset, pPdStruct);
            if (nItemSize <= 0) break;
            nCurrentOffset += nItemSize;
        }
        nResult = nCurrentOffset - nOffset;
    } else if (nType == XDEX_DEF::TYPE_CODE_ITEM) {
        qint64 nCurrentOffset = nOffset;
        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            qint64 nItemSize = getCodeItemSize(nCurrentOffset, pPdStruct);
            if (nItemSize <= 0) break;
            nCurrentOffset += nItemSize;
            if (nCurrentOffset & 3) {  // code_item is 4-byte aligned
                nCurrentOffset += 4 - (nCurrentOffset & 3);
            }
        }
        nResult = nCurrentOffset - nOffset;
    } else if (nType == XDEX_DEF::TYPE_ENCODED_ARRAY_ITEM) {
        qint64 nCurrentOffset = nOffset;
        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            qint64 nItemSize = getEncodedArrayItemSize(nCurrentOffset, pPdStruct);
            if (nItemSize <= 0) break;
            nCurrentOffset += nItemSize;
        }
        nResult = nCurrentOffset - nOffset;
    } else if (nType == XDEX_DEF::TYPE_ANNOTATION_ITEM) {
        qint64 nCurrentOffset = nOffset;
        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            qint64 nItemSize = getAnnotationItemSize(nCurrentOffset, pPdStruct);
            if (nItemSize <= 0) break;
            nCurrentOffset += nItemSize;
        }
        nResult = nCurrentOffset - nOffset;
    } else if (nType == XDEX_DEF::TYPE_ANNOTATIONS_DIRECTORY_ITEM) {
        qint64 nCurrentOffset = nOffset;
        for (qint32 i = 0; (i < nCount) && (nCurrentOffset < nFileSize) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            qint64 nItemSize = getAnnotationsDirectoryItemSize(nCurrentOffset);
            if (nItemSize <= 0) break;
            nCurrentOffset += nItemSize;
            if (nCurrentOffset & 3) {  // annotations_directory_item is 4-byte aligned
                nCurrentOffset += 4 - (nCurrentOffset & 3);
            }
        }
        nResult = nCurrentOffset - nOffset;
    } else if (nType == XDEX_DEF::TYPE_HIDDENAPI_CLASS_DATA_ITEM) {
        nResult = 0;  // variable/version-specific layout; getFileParts approximates this by section gap
    }

    return nResult;
}

QString XDEX::getFileFormatExt()
{
    return QStringLiteral("dex");
}

QString XDEX::getFileFormatExtsString()
{
    return QStringLiteral("DEX(dex)");
}

QString XDEX::getMIMEString()
{
    return QStringLiteral("application/vnd.android.dex");
}

QString XDEX::structIDToString(quint32 nID)
{
    return XBinary::XCONVERT_idToTransString(nID, _TABLE_DEX_STRUCTID, sizeof(_TABLE_DEX_STRUCTID) / sizeof(XBinary::XCONVERT));
}

QString XDEX::structIDToFtString(quint32 nID)
{
    return XBinary::XCONVERT_idToFtString(nID, _TABLE_DEX_STRUCTID, sizeof(_TABLE_DEX_STRUCTID) / sizeof(XBinary::XCONVERT));
}

quint32 XDEX::ftStringToStructID(const QString &sFtString)
{
    return XCONVERT_ftStringToId(sFtString, _TABLE_DEX_STRUCTID, sizeof(_TABLE_DEX_STRUCTID) / sizeof(XBinary::XCONVERT));
}

QList<XBinary::FPART> XDEX::getFileParts(quint32 nFileParts, qint32 nLimit, PDSTRUCT *pPdStruct)
{
    QList<XBinary::FPART> listResult;

    if ((nLimit < -1) || (nLimit == 0) || !XBinary::isPdStructNotCanceled(pPdStruct)) return listResult;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    if (!progressLifetime.isValid()) return listResult;

    XDEX_DEF::HEADER header = getHeader();

    if (nFileParts & FILEPART_HEADER) {
        listResult.append(getFPART(FILEPART_HEADER, tr("Header"), 0, header.header_size, XADDR_MAX, 0));
        if ((nLimit != -1) && (listResult.count() >= nLimit)) return listResult;
    }

    qint64 nMaxOffset = (qint64)header.data_off + (qint64)header.data_size;

    if (nFileParts & FILEPART_REGION) {
        if (appendDexRegion(&listResult, QStringLiteral("link"), header.link_off, header.link_size, nLimit)) return listResult;
        if (appendDexRegion(&listResult, QStringLiteral("string_ids"), header.string_ids_off,
                            static_cast<qint64>(header.string_ids_size) * sizeof(XDEX_DEF::STRING_ITEM_ID), nLimit))
            return listResult;
        if (appendDexRegion(&listResult, QStringLiteral("type_ids"), header.type_ids_off, static_cast<qint64>(header.type_ids_size) * sizeof(XDEX_DEF::TYPE_ITEM_ID),
                            nLimit))
            return listResult;
        if (appendDexRegion(&listResult, QStringLiteral("proto_ids"), header.proto_ids_off, static_cast<qint64>(header.proto_ids_size) * sizeof(XDEX_DEF::PROTO_ITEM_ID),
                            nLimit))
            return listResult;
        if (appendDexRegion(&listResult, QStringLiteral("field_ids"), header.field_ids_off, static_cast<qint64>(header.field_ids_size) * sizeof(XDEX_DEF::FIELD_ITEM_ID),
                            nLimit))
            return listResult;
        if (appendDexRegion(&listResult, QStringLiteral("method_ids"), header.method_ids_off,
                            static_cast<qint64>(header.method_ids_size) * sizeof(XDEX_DEF::METHOD_ITEM_ID), nLimit))
            return listResult;
        if (appendDexRegion(&listResult, QStringLiteral("class_defs"), header.class_defs_off,
                            static_cast<qint64>(header.class_defs_size) * sizeof(XDEX_DEF::CLASS_ITEM_DEF), nLimit))
            return listResult;
        if (appendDexRegion(&listResult, QStringLiteral("data"), header.data_off, header.data_size, nLimit)) return listResult;
    }

    if ((nFileParts & FILEPART_SECTION) || (nFileParts & FILEPART_OVERLAY)) {
        QMap<quint64, QString> mapTypes = getTypes();
        bool bIsBigEndian = isBigEndian();

        QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(pPdStruct);
        if (!isPdStructLifetimeAlive(progressLifetime)) return {};

        qint32 nNumberOfRecords = listMapItems.count();

        // Sorted section starts (+ format-size sentinel) used to size variable-length
        // data items (code_item, string_data_item, ...) by the gap to the next section.
        const qint64 nFormatSize = getFileFormatSize(pPdStruct);
        if (!isPdStructLifetimeAlive(progressLifetime)) return {};
        QList<qint64> listSortedOffsets;
        for (qint32 i = 0; i < nNumberOfRecords; i++) {
            if (listMapItems.at(i).nOffset > 0) {
                listSortedOffsets.append(listMapItems.at(i).nOffset);
            }
        }
        listSortedOffsets.append(nFormatSize);
        std::sort(listSortedOffsets.begin(), listSortedOffsets.end());

        for (qint32 i = 0; (i < nNumberOfRecords) && XBinary::isPdStructNotCanceled(pPdStruct); i++) {
            XDEX_DEF::MAP_ITEM mapItem = listMapItems.at(i);

            FPART record = {};
            record.nFileOffset = mapItem.nOffset;
            record.nFileSize = getDataSizeByType(mapItem.nType, mapItem.nOffset, mapItem.nCount, bIsBigEndian, pPdStruct);
            if (!isPdStructLifetimeAlive(progressLifetime)) return {};

            // getDataSizeByType returns a 1-byte placeholder for variable-length items
            // (and 0 for unknown types); span such a section to the next section start.
            if ((record.nFileSize <= 1) && (mapItem.nOffset > 0)) {
                qint64 nNextOffset = nFormatSize;

                for (qint32 j = 0; j < listSortedOffsets.count(); j++) {
                    if (listSortedOffsets.at(j) > mapItem.nOffset) {
                        nNextOffset = listSortedOffsets.at(j);
                        break;
                    }
                }

                if (nNextOffset > mapItem.nOffset) {
                    record.nFileSize = nNextOffset - mapItem.nOffset;
                }
            }

            // The header item overlaps the FILEPART_HEADER already emitted above; avoid the duplicate.
            bool bSkipSection = (nFileParts & FILEPART_HEADER) && (mapItem.nType == XDEX_DEF::TYPE_HEADER_ITEM);

            if ((nFileParts & FILEPART_SECTION) && !bSkipSection) {
                record.nVirtualAddress = XADDR_MAX;
                record.filePart = FILEPART_SECTION;
                record.sName = mapTypes.value(mapItem.nType);
                listResult.append(record);
                if ((nLimit != -1) && (listResult.count() >= nLimit)) return listResult;
            }

            if (record.nFileOffset + record.nFileSize > nMaxOffset) {
                nMaxOffset = record.nFileOffset + record.nFileSize;
            }
        }
    }

    if (nFileParts & FILEPART_OVERLAY) {
        if (nMaxOffset < getSize()) {
            listResult.append(getFPART(FILEPART_OVERLAY, tr("Overlay"), nMaxOffset, getSize() - nMaxOffset, XADDR_MAX, 0));
            if ((nLimit != -1) && (listResult.count() >= nLimit)) return listResult;
        }
    }

    return listResult;
}

bool XDEX::isStringPoolSorted(PDSTRUCT *pPdStruct)
{
    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    if (!progressLifetime.isValid()) return false;

    QList<XDEX_DEF::MAP_ITEM> mapItems = getMapItems(pPdStruct);
    if (!isPdStructLifetimeAlive(progressLifetime)) return false;

    return isStringPoolSorted(&mapItems, pPdStruct);
}

static void addDexXFTable(XDEX *pDex, const XBinary::XFSTRUCT &xfStruct, QList<XBinary::XFHEADER> *pListResult, XDEX::STRUCTID sid, qint64 nOff, qint32 nCount,
                          qint32 nRowSize, const QString &sParentTag)
{
    if (nCount <= 0 || nOff <= 0) return;
    // Clamp to what the file can actually hold: a crafted count must not balloon listRowLocations.
    nCount = (qint32)clampTableCount((quint32)nCount, nOff, nRowSize, pDex->getSize());
    if (nCount <= 0) return;
    XBinary::XFHEADER xfh = {};
    xfh.sParentTag = sParentTag;
    xfh.fileType = xfStruct.fileType;
    xfh.structID = static_cast<XBinary::STRUCTID>(sid);
    xfh.xLoc = XBinary::offsetToLoc(nOff);
    xfh.xfType = XBinary::XFTYPE_TABLE;
    xfh.listFields = pDex->getXFRecords(xfStruct.fileType, sid, xfh.xLoc);
    for (qint32 i = 0; i < nCount; i++) {
        xfh.listRowLocations.append(nOff + (qint64)i * nRowSize);
    }
    xfh.sTag = XBinary::xfHeaderToTag(xfh, pDex->structIDToString(sid), sParentTag);
    pListResult->append(xfh);
}

QList<XBinary::XFHEADER> XDEX::getXFHeaders(const XFSTRUCT &xfStruct, PDSTRUCT *pPdStruct)
{
    QList<XBinary::XFHEADER> listResult;

    PDSTRUCT pdStructEmpty = XBinary::createPdStruct();
    if (!pPdStruct) {
        pPdStruct = &pdStructEmpty;
    }
    const PDSTRUCTLIFETIME progressLifetime = retainPdStructLifetime(pPdStruct);
    if (!progressLifetime.isValid()) return listResult;

    quint32 nStructID = xfStruct.nStructID;

    XDEX_DEF::HEADER hdr = getHeader();

    if (nStructID == 0) {
        XFSTRUCT _xfStruct = xfStruct;
        _xfStruct.nStructID = STRUCTID_HEADER;
        _xfStruct.xLoc = offsetToLoc(0);
        listResult.append(getXFHeaders(_xfStruct, pPdStruct));
        if (!isPdStructLifetimeAlive(progressLifetime)) return {};
    } else if (nStructID == STRUCTID_HEADER) {
        XFHEADER xfHeader = {};
        xfHeader.sParentTag = xfStruct.sParent;
        xfHeader.fileType = xfStruct.fileType;
        xfHeader.structID = static_cast<XBinary::STRUCTID>(STRUCTID_HEADER);
        xfHeader.xLoc = offsetToLoc(0);
        xfHeader.xfType = XFTYPE_HEADER;
        xfHeader.listFields = getXFRecords(xfStruct.fileType, STRUCTID_HEADER, xfHeader.xLoc);
        xfHeader.sTag = xfHeaderToTag(xfHeader, structIDToString(STRUCTID_HEADER), xfHeader.sParentTag);
        listResult.append(xfHeader);

        if (xfStruct.bIsParent) {
            QString sParent = xfHeader.sTag;
            addDexXFTable(this, xfStruct, &listResult, STRUCTID_STRING_IDS_LIST, hdr.string_ids_off, hdr.string_ids_size, sizeof(XDEX_DEF::STRING_ITEM_ID), sParent);
            addDexXFTable(this, xfStruct, &listResult, STRUCTID_TYPE_IDS_LIST, hdr.type_ids_off, hdr.type_ids_size, sizeof(XDEX_DEF::TYPE_ITEM_ID), sParent);
            addDexXFTable(this, xfStruct, &listResult, STRUCTID_PROTO_IDS_LIST, hdr.proto_ids_off, hdr.proto_ids_size, sizeof(XDEX_DEF::PROTO_ITEM_ID), sParent);
            addDexXFTable(this, xfStruct, &listResult, STRUCTID_FIELD_IDS_LIST, hdr.field_ids_off, hdr.field_ids_size, sizeof(XDEX_DEF::FIELD_ITEM_ID), sParent);
            addDexXFTable(this, xfStruct, &listResult, STRUCTID_METHOD_IDS_LIST, hdr.method_ids_off, hdr.method_ids_size, sizeof(XDEX_DEF::METHOD_ITEM_ID), sParent);
            addDexXFTable(this, xfStruct, &listResult, STRUCTID_CLASS_DEFS_LIST, hdr.class_defs_off, hdr.class_defs_size, sizeof(XDEX_DEF::CLASS_ITEM_DEF), sParent);

            // call_site_ids and method_handles are only reachable through the map list (not the header)
            if (hdr.map_off > 0) {
                QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(pPdStruct);
                if (!isPdStructLifetimeAlive(progressLifetime)) return {};
                XDEX_DEF::MAP_ITEM miCallSite = getMapItem(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM, &listMapItems, pPdStruct);
                addDexXFTable(this, xfStruct, &listResult, STRUCTID_CALL_SITE_IDS_LIST, miCallSite.nOffset, miCallSite.nCount, sizeof(XDEX_DEF::CALL_SITE_ITEM_ID),
                              sParent);
                XDEX_DEF::MAP_ITEM miMethodHandle = getMapItem(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM, &listMapItems, pPdStruct);
                addDexXFTable(this, xfStruct, &listResult, STRUCTID_METHOD_HANDLE_LIST, miMethodHandle.nOffset, miMethodHandle.nCount,
                              sizeof(XDEX_DEF::METHOD_HANDLE_ITEM), sParent);

                qint32 nMapCount = (qint32)read_uint32(hdr.map_off, isBigEndian());
                addDexXFTable(this, xfStruct, &listResult, STRUCTID_MAP_LIST, hdr.map_off + sizeof(quint32), nMapCount, sizeof(XDEX_DEF::MAP_ITEM), sParent);
            }
        }
    } else if (nStructID == STRUCTID_STRING_IDS_LIST) {
        addDexXFTable(this, xfStruct, &listResult, STRUCTID_STRING_IDS_LIST, hdr.string_ids_off, hdr.string_ids_size, sizeof(XDEX_DEF::STRING_ITEM_ID), xfStruct.sParent);
    } else if (nStructID == STRUCTID_TYPE_IDS_LIST) {
        addDexXFTable(this, xfStruct, &listResult, STRUCTID_TYPE_IDS_LIST, hdr.type_ids_off, hdr.type_ids_size, sizeof(XDEX_DEF::TYPE_ITEM_ID), xfStruct.sParent);
    } else if (nStructID == STRUCTID_PROTO_IDS_LIST) {
        addDexXFTable(this, xfStruct, &listResult, STRUCTID_PROTO_IDS_LIST, hdr.proto_ids_off, hdr.proto_ids_size, sizeof(XDEX_DEF::PROTO_ITEM_ID), xfStruct.sParent);
    } else if (nStructID == STRUCTID_FIELD_IDS_LIST) {
        addDexXFTable(this, xfStruct, &listResult, STRUCTID_FIELD_IDS_LIST, hdr.field_ids_off, hdr.field_ids_size, sizeof(XDEX_DEF::FIELD_ITEM_ID), xfStruct.sParent);
    } else if (nStructID == STRUCTID_METHOD_IDS_LIST) {
        addDexXFTable(this, xfStruct, &listResult, STRUCTID_METHOD_IDS_LIST, hdr.method_ids_off, hdr.method_ids_size, sizeof(XDEX_DEF::METHOD_ITEM_ID), xfStruct.sParent);
    } else if (nStructID == STRUCTID_CLASS_DEFS_LIST) {
        addDexXFTable(this, xfStruct, &listResult, STRUCTID_CLASS_DEFS_LIST, hdr.class_defs_off, hdr.class_defs_size, sizeof(XDEX_DEF::CLASS_ITEM_DEF), xfStruct.sParent);
    } else if (nStructID == STRUCTID_MAP_LIST) {
        if (hdr.map_off > 0) {
            qint32 nMapCount = (qint32)read_uint32(hdr.map_off, isBigEndian());
            addDexXFTable(this, xfStruct, &listResult, STRUCTID_MAP_LIST, hdr.map_off + sizeof(quint32), nMapCount, sizeof(XDEX_DEF::MAP_ITEM), xfStruct.sParent);
        }
    } else if (nStructID == STRUCTID_CALL_SITE_IDS_LIST) {
        QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(pPdStruct);
        if (!isPdStructLifetimeAlive(progressLifetime)) return {};
        XDEX_DEF::MAP_ITEM mi = getMapItem(XDEX_DEF::TYPE_CALL_SITE_ID_ITEM, &listMapItems, pPdStruct);
        addDexXFTable(this, xfStruct, &listResult, STRUCTID_CALL_SITE_IDS_LIST, mi.nOffset, mi.nCount, sizeof(XDEX_DEF::CALL_SITE_ITEM_ID), xfStruct.sParent);
    } else if (nStructID == STRUCTID_METHOD_HANDLE_LIST) {
        QList<XDEX_DEF::MAP_ITEM> listMapItems = getMapItems(pPdStruct);
        if (!isPdStructLifetimeAlive(progressLifetime)) return {};
        XDEX_DEF::MAP_ITEM mi = getMapItem(XDEX_DEF::TYPE_METHOD_HANDLE_ITEM, &listMapItems, pPdStruct);
        addDexXFTable(this, xfStruct, &listResult, STRUCTID_METHOD_HANDLE_LIST, mi.nOffset, mi.nCount, sizeof(XDEX_DEF::METHOD_HANDLE_ITEM), xfStruct.sParent);
    }

    return listResult;
}

QList<XBinary::XFRECORD> XDEX::getXFRecords(FT fileType, quint32 nStructID, const XLOC &xLoc)
{
    Q_UNUSED(fileType)
    Q_UNUSED(xLoc)

    QList<XBinary::XFRECORD> listResult;

    if (nStructID == STRUCTID_HEADER) {
        listResult.append({"magic", (qint32)offsetof(XDEX_DEF::HEADER, magic), 4, XFRECORD_FLAG_LE, VT_UINT32});
        listResult.append({"version", (qint32)offsetof(XDEX_DEF::HEADER, version), 4, XFRECORD_FLAG_LE, VT_UINT32});
        listResult.append({"checksum", (qint32)offsetof(XDEX_DEF::HEADER, checksum), 4, XFRECORD_FLAG_NONE, VT_UINT32});
        listResult.append({"signature", (qint32)offsetof(XDEX_DEF::HEADER, signature), 20, XFRECORD_FLAG_NONE, VT_BYTE_ARRAY});
        listResult.append({"file_size", (qint32)offsetof(XDEX_DEF::HEADER, file_size), 4, XFRECORD_FLAG_SIZE, VT_UINT32});
        listResult.append({"header_size", (qint32)offsetof(XDEX_DEF::HEADER, header_size), 4, XFRECORD_FLAG_SIZE, VT_UINT32});
        listResult.append({"endian_tag", (qint32)offsetof(XDEX_DEF::HEADER, endian_tag), 4, XFRECORD_FLAG_LE, VT_UINT32});
        listResult.append({"link_size", (qint32)offsetof(XDEX_DEF::HEADER, link_size), 4, XFRECORD_FLAG_SIZE, VT_UINT32});
        listResult.append({"link_off", (qint32)offsetof(XDEX_DEF::HEADER, link_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"map_off", (qint32)offsetof(XDEX_DEF::HEADER, map_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"string_ids_size", (qint32)offsetof(XDEX_DEF::HEADER, string_ids_size), 4, XFRECORD_FLAG_COUNT, VT_UINT32});
        listResult.append({"string_ids_off", (qint32)offsetof(XDEX_DEF::HEADER, string_ids_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"type_ids_size", (qint32)offsetof(XDEX_DEF::HEADER, type_ids_size), 4, XFRECORD_FLAG_COUNT, VT_UINT32});
        listResult.append({"type_ids_off", (qint32)offsetof(XDEX_DEF::HEADER, type_ids_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"proto_ids_size", (qint32)offsetof(XDEX_DEF::HEADER, proto_ids_size), 4, XFRECORD_FLAG_COUNT, VT_UINT32});
        listResult.append({"proto_ids_off", (qint32)offsetof(XDEX_DEF::HEADER, proto_ids_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"field_ids_size", (qint32)offsetof(XDEX_DEF::HEADER, field_ids_size), 4, XFRECORD_FLAG_COUNT, VT_UINT32});
        listResult.append({"field_ids_off", (qint32)offsetof(XDEX_DEF::HEADER, field_ids_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"method_ids_size", (qint32)offsetof(XDEX_DEF::HEADER, method_ids_size), 4, XFRECORD_FLAG_COUNT, VT_UINT32});
        listResult.append({"method_ids_off", (qint32)offsetof(XDEX_DEF::HEADER, method_ids_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"class_defs_size", (qint32)offsetof(XDEX_DEF::HEADER, class_defs_size), 4, XFRECORD_FLAG_COUNT, VT_UINT32});
        listResult.append({"class_defs_off", (qint32)offsetof(XDEX_DEF::HEADER, class_defs_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"data_size", (qint32)offsetof(XDEX_DEF::HEADER, data_size), 4, XFRECORD_FLAG_SIZE, VT_UINT32});
        listResult.append({"data_off", (qint32)offsetof(XDEX_DEF::HEADER, data_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
    } else if (nStructID == STRUCTID_STRING_IDS_LIST) {
        listResult.append(
            {"string_data_off", (qint32)offsetof(XDEX_DEF::STRING_ITEM_ID, string_data_off), 4, XFRECORD_FLAG_OFFSET | XFRECORD_FLAG_OFFSET_MUTF8STRING, VT_UINT32});
    } else if (nStructID == STRUCTID_TYPE_IDS_LIST) {
        // qint64 nSpOff = (qint64)getHeader_string_ids_off();
        // qint32 nSpSize = (qint32)getHeader_string_ids_size();
        listResult.append({"descriptor_idx", (qint32)offsetof(XDEX_DEF::TYPE_ITEM_ID, descriptor_idx), 4, XFRECORD_FLAG_STRING_POOL_IDX, VT_UINT32});
    } else if (nStructID == STRUCTID_PROTO_IDS_LIST) {
        listResult.append({"shorty_idx", (qint32)offsetof(XDEX_DEF::PROTO_ITEM_ID, shorty_idx), 4, XFRECORD_FLAG_STRING_POOL_IDX, VT_UINT32});
        listResult.append({"return_type_idx", (qint32)offsetof(XDEX_DEF::PROTO_ITEM_ID, return_type_idx), 4, XFRECORD_FLAG_NONE, VT_UINT32});
        listResult.append({"parameters_off", (qint32)offsetof(XDEX_DEF::PROTO_ITEM_ID, parameters_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
    } else if (nStructID == STRUCTID_FIELD_IDS_LIST) {
        // qint64 nSpOff = (qint64)getHeader_string_ids_off();
        // qint32 nSpSize = (qint32)getHeader_string_ids_size();
        listResult.append({"class_idx", (qint32)offsetof(XDEX_DEF::FIELD_ITEM_ID, class_idx), 2, XFRECORD_FLAG_NONE, VT_UINT16});
        listResult.append({"type_idx", (qint32)offsetof(XDEX_DEF::FIELD_ITEM_ID, type_idx), 2, XFRECORD_FLAG_NONE, VT_UINT16});
        listResult.append({"name_idx", (qint32)offsetof(XDEX_DEF::FIELD_ITEM_ID, name_idx), 4, XFRECORD_FLAG_STRING_POOL_IDX, VT_UINT32});
    } else if (nStructID == STRUCTID_METHOD_IDS_LIST) {
        // qint64 nSpOff = (qint64)getHeader_string_ids_off();
        // qint32 nSpSize = (qint32)getHeader_string_ids_size();
        listResult.append({"class_idx", (qint32)offsetof(XDEX_DEF::METHOD_ITEM_ID, class_idx), 2, XFRECORD_FLAG_NONE, VT_UINT16});
        listResult.append({"proto_idx", (qint32)offsetof(XDEX_DEF::METHOD_ITEM_ID, proto_idx), 2, XFRECORD_FLAG_NONE, VT_UINT16});
        listResult.append({"name_idx", (qint32)offsetof(XDEX_DEF::METHOD_ITEM_ID, name_idx), 4, XFRECORD_FLAG_STRING_POOL_IDX, VT_UINT32});
    } else if (nStructID == STRUCTID_CLASS_DEFS_LIST) {
        listResult.append({"class_idx", (qint32)offsetof(XDEX_DEF::CLASS_ITEM_DEF, class_idx), 4, XFRECORD_FLAG_NONE, VT_UINT32});
        listResult.append({"access_flags", (qint32)offsetof(XDEX_DEF::CLASS_ITEM_DEF, access_flags), 4, XFRECORD_FLAG_NONE, VT_UINT32});
        listResult.append({"superclass_idx", (qint32)offsetof(XDEX_DEF::CLASS_ITEM_DEF, superclass_idx), 4, XFRECORD_FLAG_NONE, VT_UINT32});
        listResult.append({"interfaces_off", (qint32)offsetof(XDEX_DEF::CLASS_ITEM_DEF, interfaces_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"source_file_idx", (qint32)offsetof(XDEX_DEF::CLASS_ITEM_DEF, source_file_idx), 4, XFRECORD_FLAG_NONE, VT_UINT32});
        listResult.append({"annotations_off", (qint32)offsetof(XDEX_DEF::CLASS_ITEM_DEF, annotations_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"class_data_off", (qint32)offsetof(XDEX_DEF::CLASS_ITEM_DEF, class_data_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
        listResult.append({"static_values_off", (qint32)offsetof(XDEX_DEF::CLASS_ITEM_DEF, static_values_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
    } else if (nStructID == STRUCTID_MAP_LIST) {
        listResult.append({"type", 0, 2, XFRECORD_FLAG_NONE, VT_UINT16});
        listResult.append({"count", 4, 4, XFRECORD_FLAG_COUNT, VT_UINT32});
        listResult.append({"offset", 8, 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
    } else if (nStructID == STRUCTID_CALL_SITE_IDS_LIST) {
        listResult.append({"call_site_off", (qint32)offsetof(XDEX_DEF::CALL_SITE_ITEM_ID, call_site_off), 4, XFRECORD_FLAG_OFFSET, VT_UINT32});
    } else if (nStructID == STRUCTID_METHOD_HANDLE_LIST) {
        listResult.append({"method_handle_type", (qint32)offsetof(XDEX_DEF::METHOD_HANDLE_ITEM, method_handle_type), 2, XFRECORD_FLAG_NONE, VT_UINT16});
        listResult.append({"unused1", (qint32)offsetof(XDEX_DEF::METHOD_HANDLE_ITEM, unused1), 2, XFRECORD_FLAG_NONE, VT_UINT16});
        listResult.append({"field_or_method_id", (qint32)offsetof(XDEX_DEF::METHOD_HANDLE_ITEM, field_or_method_id), 2, XFRECORD_FLAG_NONE, VT_UINT16});
        listResult.append({"unused2", (qint32)offsetof(XDEX_DEF::METHOD_HANDLE_ITEM, unused2), 2, XFRECORD_FLAG_NONE, VT_UINT16});
    }

    return listResult;
}

QList<QString> XDEX::getSearchSignatures()
{
    QList<QString> listResult;
    listResult.append("'dex\n'......00");
    return listResult;
}

XBinary *XDEX::createInstance(QIODevice *pDevice, bool bIsImage, XADDR nModuleAddress)
{
    Q_UNUSED(bIsImage)
    Q_UNUSED(nModuleAddress)
    return new XDEX(pDevice);
}

bool XDEX::handleInternalInfo(PDSTRUCT *pPdStruct)
{
    bool bResult = true;

    if (!isInternalInfoHandled()) {
        bResult = XBinary::handleInternalInfo(pPdStruct);

        if (bResult) {
            static_cast<XBinary::INTERNAL_INFO &>(m_internalInfo) = *static_cast<XBinary::INTERNAL_INFO *>(XBinary::getInternalInfo(pPdStruct));
            setIsInternalInfoHandled(true);
        }
    }

    return bResult;
}

void *XDEX::getInternalInfo(PDSTRUCT *pPdStruct)
{
    handleInternalInfo(pPdStruct);

    return &m_internalInfo;
}

void XDEX::setInternalInfo(void *pInternalInfo)
{
    if (pInternalInfo) {
        m_internalInfo = *static_cast<INTERNAL_INFO *>(pInternalInfo);
        XBinary::setInternalInfo(static_cast<XBinary::INTERNAL_INFO *>(&m_internalInfo));
        setIsInternalInfoHandled(true);
    } else {
        m_internalInfo = INTERNAL_INFO();
        XBinary::setInternalInfo(nullptr);
        setIsInternalInfoHandled(false);
    }
}
