SUBDIRS = soap

lib_LTLIBRARIES = libcrowdclient.la
libcrowdclient_la_SOURCES = crowdclient.cpp crowdcache.cpp
libcrowdclient_la_LIBADD = $(GSOAP_LIBS) soap/libcrowdsoap.la
libcrowdclient_la_CXXFLAGS = -I$(top_srcdir)/include/ -I$(top_srcdir)/src/soap/ -I$(top_builddir)/src/soap/ $(GSOAP_CFLAGS)
libcrowdclient_la_LDFLAGS = -version-info 1:0:0

bin_PROGRAMS = crowdclient
crowdclient_SOURCES = main.cpp
crowdclient_CXXFLAGS = -I$(top_srcdir)/include/
crowdclient_LDADD = libcrowdclient.la $(GSOAP_LIBS) 

noinst_HEADERS = crowdcache_p.hpp