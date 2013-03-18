import nx_commons

print "lol"
mylog = nx_commons.nxlogger("/tmp/lol.txt", "test1")
mylog.error("this is error")
mylog.warning("this is warning")


daemon = nx_commons.nxdaemonizer("/tmp/lol.pid")
daemon.daemonize()
daemon.write_pid()
#a = 0
while True:
    pass
