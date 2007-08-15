AC_INIT()

AM_CONFIG_HEADER(config.h)
AM_INIT_AUTOMAKE(mrts, 0.2)

AC_LANG_C
AC_PROG_CC
AM_PROG_LIBTOOL
AC_LIBOBJ
AC_SUBST(LIBTOOL_DEPS)

dnl Checks for libevent version
AC_CHECK_LIB(event, bufferevent_setwatermark)

dnl Checks for header files
AC_HEADER_STDC
AC_CHECK_HEADERS(fcntl.h stdarg.h inttypes.h stdint.h unistd.h errno.h netinet/in.h sys/queue.h arpa/inet.h event.h sys/socket.h sys/time.h)

AC_OUTPUT(Makefile src/Makefile lib/Makefile include/Makefile)
