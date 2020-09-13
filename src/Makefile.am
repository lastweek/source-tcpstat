AUTOMAKE_OPTIONS = foreign no-dependencies
AM_INSTALL_PROGRAM_FLAGS = -m 755

INCLUDES = -I../include

bin_PROGRAMS = tcpstat @TCPPROF@
EXTRA_PROGRAMS = tcpprof
noinst_PROGRAMS = packetdump catpcap

tcpstat_SOURCES = tcpstat.c
tcpstat_LDADD = ../lib/libtcpstat.a @MATHLIB@
tcpstat_DEPENDENCIES = ../lib/libtcpstat.a

tcpprof_SOURCES = stats.c tcpprof.c
tcpprof_LDADD = ../lib/libtcpstat.a @LD_TCPPROF@
tcpprof_DEPENDENCIES = ../lib/libtcpstat.a

packetdump_SOURCES = dump.c
packetdump_LDADD = ../lib/libtcpstat.a
packetdump_DEPENDENCIES = ../lib/libtcpstat.a

catpcap_SOURCES = catpcap.c

