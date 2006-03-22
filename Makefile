ifndef NAVISERVER
    NAVISERVER  = /usr/local/ns
endif

#
# Module name
#
MOD      =  nssyslogd.so

#
# Objects to build.
#
OBJS     = nssyslogd.o

PROCS   = syslogd_procs.tcl

INSTALL += install-procs

install-procs: $(PROCS)
	for f in $(PROCS); do $(INSTALL_SH) $$f $(INSTTCL)/; done

include  $(NAVISERVER)/include/Makefile.module

