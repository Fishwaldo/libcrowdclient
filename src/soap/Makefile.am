noinst_LTLIBRARIES = libcrowdsoap.la
#libcrowdsoap_la_SOURCES = soapC.cpp soapSecurityServerHttpBindingProxy.cpp 
libcrowdsoap_la_CXXFLAGS = 
libcrowdsoap_la_LDFLAGS = 

noinst_HEADERS = crowdsoap.h

nodist_libcrowdsoap_la_SOURCES = soapC.cpp soapSecurityServerHttpBindingProxy.cpp


BUILT_SOURCES = soapC.cpp soapSecurityServerHttpBindingProxy.cpp soapSecurityServerHttpBindingProxy.h soapH.h soapStub.h SecurityServerHttpBinding.nsmap

CLEANFILES = soapC.cpp soapSecurityServerHttpBindingProxy.cpp soapSecurityServerHttpBindingProxy.h soapH.h soapStub.h SecurityServerHttpBinding.nsmap

soapC.cpp: crowdsoap.h
	@PROG_SOAPCPP2@ -C -i -w -x $(top_srcdir)/src/soap/crowdsoap.h

soapSecurityServerHttpBindingProxy.cpp: soapC.cpp	

soapSecurityServerHttpBindingProxy.h: soapC.cpp

SecurityServerHttpBinding.nsmap: soapC.cpp
