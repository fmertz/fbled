dnl Process this file with autoconf to produce a configure script.
dnl Created by Anjuta application wizard.

AC_INIT(fbled, 0.1.3.2, fireboxled@gmail.com)


m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AM_INIT_AUTOMAKE(AC_PACKAGE_NAME, AC_PACKAGE_VERSION)
AC_CONFIG_HEADERS([config.h])
AM_MAINTAINER_MODE

AC_PROG_CC
##
##	fbled-specific tests
##
fbled_needs_pcap="no"

# Test for required functions
#
AC_CHECK_FUNCS(getifaddrs,,)
AC_CHECK_FUNCS(getloadavg,,)
AC_CHECK_FUNCS(i386_set_ioperm,,)
AC_CHECK_FUNCS(ioperm,,)

# Test for headers
# 
AC_CHECK_HEADERS(stdio.h stdlib.h unistd.h string.h sys/types.h time.h signal.h fcntl.h sys/socket.h \
	errno.h sys/time.h ifaddrs.h features.h sys/io.h sys/uio.h sys/times.h asm/types.h \
	machine/sysarch.h net/if_dl.h \
	pcap/pcap.h)

AC_CHECK_HEADERS(linux/netdevice.h, [], [],
[
#if HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])

AC_CHECK_HEADERS(linux/netlink.h, [], [],
[
#if HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])

AC_CHECK_HEADERS(linux/if.h, [], [],
[
#if HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])

AC_CHECK_HEADERS(linux/if_link.h, [], [],
[
#if HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])

AC_CHECK_HEADERS(linux/netfilter_ipv4/ipt_ULOG.h, [], [], [-])
AC_CHECK_HEADERS(net/if.h, [], [],
[
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
])

AC_CHECK_HEADERS(net/if_pflog.h, [fbled_needs_pcap="yes"], [],
[
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#if HAVE_NET_IF_H
#  include <net/if.h>
#endif
])

AC_CHECK_HEADERS(machine/cpufunc.h, [], [],
[
#include <sys/types.h>
])

# Test for struct
#
AC_CHECK_MEMBERS([struct tms.tms_utime, struct tms.tms_stime],,,[#include <sys/times.h>])
AC_CHECK_MEMBERS([struct sockaddr_ll.sll_addr],,,
[
#include <sys/socket.h>
#include <linux/netdevice.h>
])
AC_CHECK_MEMBERS([struct sockaddr_dl.sdl_data, struct sockaddr_dl.sdl_nlen],,,
[
#include <sys/types.h>
#include <net/if_dl.h>
])
AC_CHECK_MEMBERS([struct rtnl_link_stats.rx_packets, struct rtnl_link_stats.tx_packets],,,
[
#include <sys/socket.h>
#include <linux/if_link.h>
])
AC_CHECK_MEMBERS([struct if_data.ifi_ipackets, struct if_data.ifi_opackets],,,
[
#include <sys/types.h>
#if HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#include <net/if.h>
])

# Test for Libraries
#
AM_CONDITIONAL(BUILD_WITH_LIB_PCAP, test "x$fbled_needs_pcap" = "xyes")

AC_OUTPUT([
Makefile
])
