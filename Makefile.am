## Process this file with automake to produce Makefile.in

## Created by Anjuta

AM_CPPFLAGS = \
	-DPACKAGE_DATA_DIR=\""$(datadir)"\" 

AM_CFLAGS = \
	 -Wall \
	 -g

bin_PROGRAMS = fbled

fbled_SOURCES = \
	fbled.c \
	fbled.h

fbled_LDADD =

if BUILD_WITH_LIB_PCAP
fbled_LDADD += -lpcap
endif

fbled_LDFLAGS =

