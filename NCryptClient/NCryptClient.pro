QT       += core gui network sql

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    connectiondialog.cpp \
    connectionmanager.cpp \
    conversationcard.cpp \
    defaultscreen.cpp \
    main.cpp \
    mainwindow.cpp \
    messagecard.cpp \
    privatemessages.cpp \
    registrationdialog.cpp \
    servers.cpp \
    settings.cpp

HEADERS += \
    connectiondialog.h \
    connectionmanager.h \
    conversationcard.h \
    defaultscreen.h \
    mainwindow.h \
    messagecard.h \
    privatemessages.h \
    registrationdialog.h \
    servers.h \
    settings.h

FORMS += \
    connectiondialog.ui \
    conversationcard.ui \
    defaultscreen.ui \
    mainwindow.ui \
    messagecard.ui \
    privatemessages.ui \
    registrationdialog.ui \
    servers.ui \
    settings.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

include($$PWD/../Qt-Secret/src/Qt-Secret.pri)

RESOURCES += \
    certs.qrc \
    images.qrc
