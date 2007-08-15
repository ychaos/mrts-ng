
# set the include path found by configure
INCLUDES = -I$(top_srcdir)/include -I/usr/local/include $(all_includes)

# the library search path.
bin_PROGRAMS = server client iecasdutest
client_SOURCES =  client.c
server_SOURCES =  server.c
client_LDADD = $(top_builddir)/lib/libiecsock.la -levent
server_LDADD = $(top_builddir)/lib/libiecsock.la -levent
AM_CFLAGS = -Wall

iecasdutest_SOURCES =  iecasdutest.c
iecasdutest_LDADD = $(top_builddir)/lib/libiecasdu.la
