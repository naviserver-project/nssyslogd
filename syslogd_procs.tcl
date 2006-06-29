# Author: Vlad Seryakov vlad@crystalballinc.com
# March 2006

namespace eval syslog {

}

ns_schedule_proc -once 0 syslog::init

# Global Syslog initialization
proc syslog::init {} {

    #ns_syslogd create mailog [ns_info home]/logs/mail.log
    #ns_syslogd create authlog [ns_info home]/logs/auth.log
    #ns_syslogd create syslog [ns_info home]/logs/syslog.log
}

# Syslog handler
proc syslog::server { args } {

    set line [ns_syslogd req]
    set facility [ns_syslogd req facility]
    set severity [ns_syslogd req severity]

    switch -glob -- $facility.$severity {
     mail.* {
        #ns_syslogd write mailog $line
        #return 1
     }

     auth.* -
     security.* -
     audit.* {
        #ns_syslogd write authlog $line
        #return 1
     }

     daemon.* {
        #ns_syslogd write syslog $line
        #return 1
     }
    }
    # Log the message to nsd.log
    return
}
