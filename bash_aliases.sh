#######################
##  network aliases  ##
#######################
# listen in all interfaces in the given port
alias ncl='nc -lvp'            # ncl <port>

# sniff traffic from the specified interface
alias sniff='sudo tcpdump -i'  # sniff <interface>

# show ports opened
alias ports='netstat -tulanp' 


#######################
##  system aliases   ##
#######################
# clean system cache
alias cleancache='echo 3 | sudo tee -a /proc/sys/vm/drop_caches'

# clean os deleting not needed packets
alias cleanos='sudo apt-get autoremove && sudo apt-get autoclean'

# flush dns 
alias flushdns='sudo systemd-resolve --flush-caches'

# list process that consume more memory
alias topmem='ps aux --sort=-%mem | head'

# list process that consume more cpu
alias topcpu='ps aux --sort=-%cpu | head'

# update upgrade system
alias update='sudo apt update && sudo apt upgrade'

# grep a process case insensitive
alias psg='ps aux | grep -v grep | grep -i'  # psg ssh

# show system logs
alias syslog='tail -f /var/log/syslog'

# show kernel logs
alias kernlog='tail -f /var/log/kern.log'