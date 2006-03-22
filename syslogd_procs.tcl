# Author: Vlad Seryakov vlad@crystalballinc.com
# March 2006

namespace eval syslog {

}

ns_schedule_proc -once 0 syslog::init

# Global Syslog initialization
proc syslog::init {} {

    ns_syslogd create mailog [ns_info home]/logs/mail.log
    ns_syslogd create authlog [ns_info home]/logs/auth.log
    ns_syslogd create syslog [ns_info home]/logs/syslog.log
}

# Syslog handler
proc syslog::server { ipaddr severity facility args } {

    switch -glob -- $facility.$severity {
     mail.* {
        ns_syslogd write mailog $args
        return 1
     }

     auth.* -
     security.* -
     audit.* {
        ns_syslogd write authlog $args
        return 1
     }

     daemon.* {
        ns_syslogd write syslog $args
        return 1
     }
    }
    # Log the message to nsd.log
    return
}
