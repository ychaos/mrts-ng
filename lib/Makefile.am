INCLUDES = -I$(top_srcdir)/include -I/usr/local/include
METASOURCES = AUTO
lib_LTLIBRARIES = libiecsock.la libiecasdu.la
libiecsock_la_SOURCES =  iecsock.c
libiecsock_la_LIBADD = -levent
libiecsock_la_LDFLAGS = -release @VERSION@ -shrext .so
libiecasdu_la_SOURCES =  libiecasdu.c
libiecasdu_la_LDFLAGS = -release @VERSION@ -shrext .so
AM_CFLAGS = -Wall

