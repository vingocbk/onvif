cp ~/gsoap-2.8/gsoap/typemap.dat .

wsdl2h -O4 -P -x -o onvif.h \
  http://www.onvif.org/onvif/ver10/device/wsdl/devicemgmt.wsdl \
  http://www.onvif.org/onvif/ver10/events/wsdl/event.wsdl \
  http://www.onvif.org/onvif/ver10/deviceio.wsdl \
  http://www.onvif.org/onvif/ver20/imaging/wsdl/imaging.wsdl \
  http://www.onvif.org/onvif/ver10/media/wsdl/media.wsdl \
  http://www.onvif.org/onvif/ver20/ptz/wsdl/ptz.wsdl \
  http://www.onvif.org/onvif/ver10/network/wsdl/remotediscovery.wsdl \
  http://www.onvif.org/ver10/advancedsecurity/wsdl/advancedsecurity.wsdl

soapcpp2 -2 -C -I ~/gsoap-2.8/gsoap -j -x onvif.h

soapcpp2 -a -x -L -pwsdd -I ~/gsoap-2.8/gsoap/import ~/gsoap-2.8/gsoap/import/wsdd5.h

c++ -g -o ipcamera -Wall -DWITH_OPENSSL -DWITH_DOM -DWITH_ZLIB \
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