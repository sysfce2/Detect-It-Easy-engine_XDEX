INCLUDEPATH += $$PWD
DEPENDPATH += $$PWD

HEADERS += \
    $$PWD/xdex.h \
    $$PWD/xdex_def.h

SOURCES += \
    $$PWD/xdex.cpp

# Shared with XArchive/xzip.pri (XAPK needs the AXML parser); the same flag
# guards both copies so the sources are compiled exactly once.
!contains(XCONFIG, xandroidbinary_sources) {
    XCONFIG += xandroidbinary_sources
    HEADERS += \
        $$PWD/xandroidbinary.h \
        $$PWD/xandroidbinary_def.h
    SOURCES += \
        $$PWD/xandroidbinary.cpp
}

!contains(XCONFIG, xbinary) {
    XCONFIG += xbinary
    include($$PWD/../Formats/xbinary.pri)
}

DISTFILES += \
    $$PWD/LICENSE \
    $$PWD/README.md \
    $$PWD/xdex.cmake
