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
#ifndef XDEX_H
#define XDEX_H

#include "xbinary.h"
#include "xdex_def.h"

class XDEX : public XBinary {
    Q_OBJECT

public:
    struct INTERNAL_INFO : XBinary::INTERNAL_INFO {};

    virtual bool handleInternalInfo(PDSTRUCT *pPdStruct) override;
    virtual void *getInternalInfo(PDSTRUCT *pPdStruct) override;
    virtual void setInternalInfo(void *pInternalInfo) override;

    enum TYPE {
        TYPE_UNKNOWN = 0,
        TYPE_MAINMODULE
        // TODO more
        // TODO main module !!! TODO Check
        // TODO the second module ...
    };

    // Decoded encoded_value (non-recursive: arrays/annotations expose a nested offset instead of by-value children, so this stays Qt6-safe).
    struct ENCODED_VALUE {
        quint8 nValueType;     // 0x00..0x1f
        quint8 nValueArg;      // high 3 bits of the header byte
        quint64 nValueRaw;     // assembled little-endian payload: scalar bits / pool index / bool (0/1)
        qint64 nNestedOffset;  // VALUE_ARRAY / VALUE_ANNOTATION: file offset of the nested structure; else -1
        qint64 nSize;          // total bytes consumed by this encoded_value
    };

    // Parsed class_data_item (encoded fields/methods with delta-decoded indices).
    struct CLASS_DATA {
        quint32 static_fields_size;
        quint32 instance_fields_size;
        quint32 direct_methods_size;
        quint32 virtual_methods_size;
        QList<XDEX_DEF::ENCODED_FIELD> listStaticFields;
        QList<XDEX_DEF::ENCODED_FIELD> listInstanceFields;
        QList<XDEX_DEF::ENCODED_METHOD> listDirectMethods;
        QList<XDEX_DEF::ENCODED_METHOD> listVirtualMethods;
    };

    enum STRUCTID {
        STRUCTID_UNKNOWN = 0,
        STRUCTID_HEADER,
        STRUCTID_STRING_IDS_LIST,
        STRUCTID_TYPE_IDS_LIST,
        STRUCTID_PROTO_IDS_LIST,
        STRUCTID_FIELD_IDS_LIST,
        STRUCTID_METHOD_IDS_LIST,
        STRUCTID_CLASS_DEFS_LIST,
        STRUCTID_DATA_LIST,
        STRUCTID_LINK_LIST,
        STRUCTID_MAP_LIST,
        STRUCTID_CALL_SITE_IDS_LIST,
        STRUCTID_METHOD_HANDLE_LIST,
    };

    XDEX(QIODevice *pDevice);
    virtual ~XDEX();

    static MODE getMode(QIODevice *pDevice);
    virtual bool isValid(PDSTRUCT *pPdStruct = nullptr) override;
    static bool isValid(QIODevice *pDevice, PDSTRUCT *pPdStruct = nullptr);
    quint32 _getVersion();
    virtual QString getVersion() override;
    virtual ENDIAN getEndian() override;
    virtual MODE getMode() override;
    virtual QString getArch() override;
    virtual bool isExecutable() override;
    virtual OSNAME getOsName() override;
    virtual QString getOsVersion() override;
    virtual FT getFileType() override;
    virtual qint32 getType() override;
    virtual QString typeIdToString(qint32 nType) override;
    virtual QString getMIMEString() override;
    virtual QString getInfo(PDSTRUCT *pPdStruct = nullptr) override;

    virtual bool isImportPresent() override;
    virtual bool isExportPresent() override;
    virtual bool isSymbolsPresent() override;

    virtual QVector<XIMPORT_STRUCT> getImportStructs() override;
    virtual QVector<XEXPORT_STRUCT> getExportStructs() override;
    virtual QVector<XSYMBOL_STRUCT> getSymbolStructs() override;

    virtual QList<MAPMODE> getMapModesList() override;
    virtual _MEMORY_MAP getMemoryMap(MAPMODE mapMode = MAPMODE_UNKNOWN, PDSTRUCT *pPdStruct = nullptr) override;
    virtual qint64 getFileFormatSize(PDSTRUCT *pPdStruct) override;

    quint32 getHeader_magic();
    quint32 getHeader_version();
    quint32 getHeader_checksum();
    QByteArray getHeader_signature();
    quint32 getHeader_file_size();
    quint32 getHeader_header_size();
    quint32 getHeader_endian_tag();
    quint32 getHeader_link_size();
    quint32 getHeader_link_off();
    quint32 getHeader_map_off();
    quint32 getHeader_string_ids_size();
    quint32 getHeader_string_ids_off();
    quint32 getHeader_type_ids_size();
    quint32 getHeader_type_ids_off();
    quint32 getHeader_proto_ids_size();
    quint32 getHeader_proto_ids_off();
    quint32 getHeader_field_ids_size();
    quint32 getHeader_field_ids_off();
    quint32 getHeader_method_ids_size();
    quint32 getHeader_method_ids_off();
    quint32 getHeader_class_defs_size();
    quint32 getHeader_class_defs_off();
    quint32 getHeader_data_size();
    quint32 getHeader_data_off();

    void setHeader_magic(quint32 value);
    void setHeader_version(quint32 value);
    void setHeader_checksum(quint32 value);
    void setHeader_file_size(quint32 value);
    void setHeader_header_size(quint32 value);
    void setHeader_endian_tag(quint32 value);
    void setHeader_link_size(quint32 value);
    void setHeader_link_off(quint32 value);
    void setHeader_map_off(quint32 value);
    void setHeader_string_ids_size(quint32 value);
    void setHeader_string_ids_off(quint32 value);
    void setHeader_type_ids_size(quint32 value);
    void setHeader_type_ids_off(quint32 value);
    void setHeader_proto_ids_size(quint32 value);
    void setHeader_proto_ids_off(quint32 value);
    void setHeader_field_ids_size(quint32 value);
    void setHeader_field_ids_off(quint32 value);
    void setHeader_method_ids_size(quint32 value);
    void setHeader_method_ids_off(quint32 value);
    void setHeader_class_defs_size(quint32 value);
    void setHeader_class_defs_off(quint32 value);
    void setHeader_data_size(quint32 value);
    void setHeader_data_off(quint32 value);

    XDEX_DEF::HEADER getHeader();
    XDEX_DEF::HEADER _readHEADER(qint64 nOffset);
    quint32 getHeaderSize();
    QList<XDEX_DEF::MAP_ITEM> getMapItems(PDSTRUCT *pPdStruct = nullptr);

    static bool compareMapItems(QList<XDEX_DEF::MAP_ITEM> *pListMaps, QList<quint16> *pListIDs, PDSTRUCT *pPdStruct = nullptr);
    static quint32 getMapItemsHash(QList<XDEX_DEF::MAP_ITEM> *pListMaps, PDSTRUCT *pPdStruct);
    static bool isMapItemPresent(quint16 nType, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct = nullptr);

    static QMap<quint64, QString> getTypes();
    static QMap<quint64, QString> getTypesS();
    static XDEX_DEF::MAP_ITEM getMapItem(quint16 nType, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct);

    QList<XDEX_DEF::STRING_ITEM_ID> getList_STRING_ITEM_ID(PDSTRUCT *pPdStruct);
    QList<XDEX_DEF::STRING_ITEM_ID> getList_STRING_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct);
    QList<XDEX_DEF::TYPE_ITEM_ID> getList_TYPE_ITEM_ID(PDSTRUCT *pPdStruct);
    QList<XDEX_DEF::TYPE_ITEM_ID> getList_TYPE_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct);
    QList<XDEX_DEF::PROTO_ITEM_ID> getList_PROTO_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct);
    QList<XDEX_DEF::FIELD_ITEM_ID> getList_FIELD_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct = nullptr);
    QList<XDEX_DEF::METHOD_ITEM_ID> getList_METHOD_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct = nullptr);
    QList<XDEX_DEF::CLASS_ITEM_DEF> getList_CLASS_ITEM_DEF(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct = nullptr);
    QList<XDEX_DEF::CALL_SITE_ITEM_ID> getList_CALL_SITE_ITEM_ID(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct = nullptr);
    QList<XDEX_DEF::METHOD_HANDLE_ITEM> getList_METHOD_HANDLE_ITEM(QList<XDEX_DEF::MAP_ITEM> *pListMapItems, PDSTRUCT *pPdStruct = nullptr);

    // MUTF-8 (Modified UTF-8) decoding — DEX/Java string encoding: 0xC0 0x80 null and CESU-8 surrogate pairs.
    static QString _mutf8ToUnicode(const char *pData, qint32 nSize);
    static QString _readMUTF8String(const char *pData, qint32 nMaxSize);
    static QString _readMUTF8String(qint64 nOffset, char *pData, qint32 nDataSize, qint32 nDataOffset);
    QString _readMUTF8String(qint64 nOffset);

    // Variable-length data-section structures.
    CLASS_DATA getClassData(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr);
    XDEX_DEF::CODE_ITEM readCodeItem(qint64 nOffset);
    QList<quint32> getProtoParameterTypes(quint32 nProtoIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct = nullptr);

    // Exact byte sizes of variable-length data items (device-walked, cancelable, file-bounded).
    qint64 getStringDataItemSize(qint64 nOffset);
    qint64 getDebugInfoItemSize(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr);
    qint64 getClassDataItemSize(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr);
    qint64 getCodeItemSize(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr);
    qint64 getEncodedValueSize(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr, qint32 nDepth = 0);
    qint64 getEncodedArrayItemSize(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr, qint32 nDepth = 0);
    qint64 getEncodedAnnotationSize(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr, qint32 nDepth = 0);
    qint64 getAnnotationItemSize(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr);
    qint64 getAnnotationsDirectoryItemSize(qint64 nOffset);

    static QString getAccessFlagsString(quint32 nAccessFlags);

    // Human-readable Java descriptor / signature rendering.
    static QString descriptorToString(const QString &sDescriptor);
    QString getClassString(quint32 nTypeIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct = nullptr);
    QString getProtoString(quint32 nProtoIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct = nullptr);
    QString getMethodString(quint32 nMethodIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct = nullptr);
    QString getFieldString(quint32 nFieldIndex, QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct = nullptr);

    // Encoded value decoding (annotations, static field initializers).
    qint64 readEncodedValue(qint64 nOffset, ENCODED_VALUE *pValue, PDSTRUCT *pPdStruct = nullptr, qint32 nDepth = 0);
    QList<ENCODED_VALUE> readEncodedArray(qint64 nOffset, PDSTRUCT *pPdStruct = nullptr);
    static QString encodedValueToString(const ENCODED_VALUE &encodedValue);

    QList<QString> getStrings(QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct = nullptr);
    QString _getString(XDEX_DEF::MAP_ITEM map_stringIdItem, quint32 nIndex, bool bIsBigEndian);
    QString _getString(XDEX_DEF::MAP_ITEM map_stringIdItem, quint32 nIndex, bool bIsBigEndian, char *pData, qint32 nDataSize, qint32 nDataOffset);
    QString _getTypeItemtString(XDEX_DEF::MAP_ITEM map_stringIdItem, XDEX_DEF::MAP_ITEM map_typeItemId, quint32 nIndex, bool bIsBigEndian);
    QList<quint32> _getTypeList(qint64 nOffset, bool bIsBigEndian, PDSTRUCT *pPdStruct);
    QList<QString> getTypeItemStrings(QList<XDEX_DEF::MAP_ITEM> *pMapItems, QList<QString> *pListStrings, PDSTRUCT *pPdStruct = nullptr);
    void getProtoIdItems(QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct);
    QString getStringItemIdString(XDEX_DEF::STRING_ITEM_ID stringItemId);
    QString getStringItemIdString(XDEX_DEF::STRING_ITEM_ID stringItemId, char *pData, qint32 nDataSize, qint32 nDataOffset);
    QString getStringItemIdString(QList<XDEX_DEF::STRING_ITEM_ID> *pList, qint32 nIndex, char *pData, qint32 nDataSize, qint32 nDataOffset);
    QString getTypeItemIdString(XDEX_DEF::TYPE_ITEM_ID typeItemId, XDEX_DEF::MAP_ITEM *pMapItemStrings);
    QString getTypeItemIdString(XDEX_DEF::TYPE_ITEM_ID typeItemId, XDEX_DEF::MAP_ITEM *pMapItemStrings, char *pData, qint32 nDataSize, qint32 nDataOffset);
    QString getTypeItemIdString(QList<XDEX_DEF::TYPE_ITEM_ID> *pList, qint32 nIndex, XDEX_DEF::MAP_ITEM *pMapItemStrings, char *pData, qint32 nDataSize,
                                qint32 nDataOffset);
    QString getProtoItemIdString(XDEX_DEF::PROTO_ITEM_ID protoItemId, XDEX_DEF::MAP_ITEM *pMapItemStrings, XDEX_DEF::MAP_ITEM *pMapItemTypes = nullptr);

    static QMap<quint64, QString> getHeaderMagics();
    static QMap<quint64, QString> getHeaderVersions();
    static QMap<quint64, QString> getHeaderEndianTags();

    static const QString PREFIX_Type;

    bool isStringPoolSorted(PDSTRUCT *pPdStruct);
    bool isStringPoolSorted(QList<XDEX_DEF::MAP_ITEM> *pMapItems, PDSTRUCT *pPdStruct);
    bool isFieldNamesUnicode(QList<XDEX_DEF::FIELD_ITEM_ID> *pListIDs, QList<QString> *pListStrings, PDSTRUCT *pPdStruct);
    bool isMethodNamesUnicode(QList<XDEX_DEF::METHOD_ITEM_ID> *pListIDs, QList<QString> *pListStrings, PDSTRUCT *pPdStruct);

    qint64 getDataSizeByType(qint32 nType, qint64 nOffset, qint32 nCount, bool bIsBigEndian, PDSTRUCT *pPdStruct);

    virtual QString getFileFormatExt() override;
    virtual QString getFileFormatExtsString() override;

    virtual QString structIDToString(quint32 nID) override;
    virtual QString structIDToFtString(quint32 nID) override;
    virtual quint32 ftStringToStructID(const QString &sFtString) override;
    virtual QList<XFHEADER> getXFHeaders(const XFSTRUCT &xfStruct, PDSTRUCT *pPdStruct) override;
    virtual QList<XFRECORD> getXFRecords(FT fileType, quint32 nStructID, const XLOC &xLoc) override;
    // virtual QList<DATA_HEADER> getDataHeaders(const DATA_HEADERS_OPTIONS &dataHeadersOptions, PDSTRUCT *pPdStruct) override;

    virtual QList<FPART> getFileParts(quint32 nFileParts, qint32 nLimit = -1, PDSTRUCT *pPdStruct = nullptr) override;
    virtual QList<QString> getSearchSignatures() override;
    virtual XBinary *createInstance(QIODevice *pDevice, bool bIsImage = false, XADDR nModuleAddress = -1) override;

private:
    QVector<XSYMBOL_STRUCT> _getSymbolStructs();
    bool _hasUnicodeNameInList(const QList<quint32> &nameIndices, QList<QString> *pListStrings, PDSTRUCT *pPdStruct) const;
    // Signed LEB128 decode (returns value; byte-size via out-param). Used for encoded_catch_handler.size.
    qint64 _readSleb128(qint64 nOffset, qint32 nMax, qint32 *pnByteSize);
    // Resolve a type-pool index to its raw Java descriptor ("Lpkg/Cls;", "[I", "V", ...).
    QString _typeIndexToDescriptor(quint32 nTypeIndex, XDEX_DEF::MAP_ITEM *pMapStrings, XDEX_DEF::MAP_ITEM *pMapTypes);

private:
    INTERNAL_INFO m_internalInfo;
};

#endif  // XDEX_H
