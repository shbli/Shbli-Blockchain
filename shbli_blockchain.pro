
TEMPLATE = app
TARGET = shbli_blockchain


SOURCES += \
    main.cpp

    #brew install openssl@1.1
    _OPENSSL_PATH = /usr/local/Cellar/openssl@1.1/1.1.0h
    INCLUDEPATH += "$${_OPENSSL_PATH}/include/"
    LIBS += -L$${_OPENSSL_PATH}/lib
    LIBS += -lssl -lcrypto # using dynamic lib (not sure if you need that "-mt" at the end or not)
