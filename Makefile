CC=c++
CFLAGS=-I.

ipcamera: g++ -g -o ipcamera -Wall -DWITH_OPENSSL -DWITH_DOM -DWITH_ZLIB \
  -I. -I ~/gsoap-2.8/gsoap/plugin -I ~/gsoap-2.8/gsoap/custom -I ~/gsoap-2.8/gsoap \
  main.cpp \
  soapC.cpp \
  wsddClient.cpp \
  wsddServer.cpp \
  soapAdvancedSecurityServiceBindingProxy.cpp \
  soapDeviceBindingProxy.cpp \
  soapDeviceIOBindingProxy.cpp \
  soapImagingBindingProxy.cpp \
  soapMediaBindingProxy.cpp \
  soapPTZBindingProxy.cpp \
  soapPullPointSubscriptionBindingProxy.cpp \
  soapRemoteDiscoveryBindingProxy.cpp \
  ~/gsoap-2.8/gsoap/stdsoap2.cpp \
  ~/gsoap-2.8/gsoap/dom.cpp \
  ~/gsoap-2.8/gsoap/plugin/smdevp.c \
  ~/gsoap-2.8/gsoap/plugin/mecevp.c \
  ~/gsoap-2.8/gsoap/plugin/wsaapi.c \
  ~/gsoap-2.8/gsoap/plugin/wsseapi.c \
  ~/gsoap-2.8/gsoap/plugin/wsddapi.c \
  ~/gsoap-2.8/gsoap/custom/struct_timeval.c \
  -lcrypto -lssl -lz
     