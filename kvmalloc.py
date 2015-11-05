#!/usr/bin/env python

import getopt
import time
import errno
import os
import sys
import re
import atexit
import multiprocessing
import libvirt
from datetime import datetime

if sys.platform == 'win32':
    print "Windows is not supported."
    exit(0)

try:
    import hashlib
    md5_new = hashlib.md5
except ImportError:
    import md5
    md5_new = md5.new


class Daemon:
    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile

    def daemonize(self):
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        os.chdir("/")
        os.setsid()
        os.umask(0)

        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError, e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(os.getpid())
        file(self.pidfile, 'w+').write("%s\n" % pid)

    def delpid(self):
        os.remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = "pidfile %s already exists. kvmalloc is already running.\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run()

    def stop(self):
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. kvmalloc daemon is not running.\n"
            sys.stderr.write(message % self.pidfile)
            return  # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                os.kill(pid, 7)
                time.sleep(0.1)
        except OSError, err:
            err = str(err)
            if err.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                print str(err)
                sys.exit(1)

    def restart(self):
        self.stop()
        self.start()

    def run(self):
        """
        Override this method with a Daemon subclass
        """


class Proc:
    def __init__(self):
        self.proc = '/proc'

    def path(self, *args):
        return os.path.join(self.proc, *(str(a) for a in args))

    def open(self, *args):
        try:
            return open(self.path(*args))
        except (IOError, OSError):
            val = sys.exc_info()[1]
            if val.errno == errno.ENOENT or val.errno == errno.EPERM:  # kernel thread or process is gone
                raise LookupError
            raise


def parse_options():
    try:
        long_options = ['full-args', 'help', 'total', 'verbose', 'sparse']
        opts, args = getopt.getopt(sys.argv[1:], "fhtvsd:p:n:c:w:l:", long_options)
    except getopt.GetoptError:
        sys.stderr.write(display_help())
        sys.exit(3)

    if len(args):
        sys.stderr.write("Unknown arguments: %s\n" % args)
        sys.exit(3)

    daemon_cmd = None
    logfile_location = None
    split_args = False
    pids_to_show = None
    proc_names_to_show = None
    cpus_to_show = None
    watch = None
    only_total = False
    verbose = False
    sparse = False

    for o, a in opts:
        if o in ('-d',):
            daemon_cmd = a
        if o in ('-l',):
            logfile_location = a
        if o in ('-f', '--full-args'):
            split_args = True
        if o in ('-t', '--total'):
            only_total = True
        if o in ('-v', '--verbose'):
            verbose = True
        if o in ('-s', '--sparse'):
            sparse = True
        if o in ('-h', '--help'):
            sys.stdout.write(display_help())
            sys.exit(0)
        if o in ('-n',):
            try:
                proc_names_to_show = [str(x) for x in a.split(',')]
            except:
                sys.stderr.write(display_help())
                sys.exit(3)
        if o in ('-p',):
            try:
                pids_to_show = [int(x) for x in a.split(',')]
            except:
                sys.stderr.write(display_help())
                sys.exit(3)
        if o in ('-c',):
            try:
                cpus_to_show = [int(x) for x in a.split(',')]
            except:
                sys.stderr.write(display_help())
                sys.exit(3)
        if o in ('-w',):
            try:
                watch = int(a)
            except:
                sys.stderr.write(display_help())
                sys.exit(3)
    return daemon_cmd, logfile_location, split_args, pids_to_show, cpus_to_show, \
        proc_names_to_show, watch, only_total, verbose, sparse


def display_help():
    help_msg = 'Usage: kvmalloc [OPTION]...\n' \
               '\n' \
               '  -h, -help                   Show this help\n' \
               '  -v  --verbose               Verbose output shows thread cpu allocation\n'\
               '  -n <process>                Name of hypervisor process (default: qemu-kvm)\n' \
               '  -w <N>                      Check stats every N seconds\n' \
               '  -d (start|stop|restart)     Start, stop, or restart kvmalloc as a daemon\n' \
               '  -l <logfile>                Logfile path when running kvmalloc as a daemon (-d)\n\n'
    return help_msg


def kernel_ver():
    kv = proc.open('sys/kernel/osrelease').readline().split(".")[:3]
    last = len(kv)
    if last == 2:
        kv.append('0')
    last -= 1
    while last > 0:
        for char in "-_":
            kv[last] = kv[last].split(char)[0]
        try:
            int(kv[last])
        except:
            kv[last] = 0
        last -= 1
    return int(kv[0]), int(kv[1]), int(kv[2])  # (major,minor,release)


def human(num, power="K", units=None):
    if num == 0.0:
        return ""
    if units is None:
        powers = ["K", "M", "G", "T"]
        while num >= 1000:  # 4 digits
            num /= 1024.0
            power = powers[powers.index(power) + 1]
        return "%.1f %sB" % (num, power)
    else:
        return "%.f" % ((num * 1024) / units)


def get_cmd_name(pid, split_args):
    cmdline = proc.open(pid, 'cmdline').read().split("\0")

    if cmdline[-1] == '' and len(cmdline) > 1:
        cmdline = cmdline[:-1]

    path = proc.path(pid, 'exe')

    try:
        path = os.readlink(path)
        path = path.split('\0')[0]
    except OSError:
        val = sys.exc_info()[1]
        if val.errno == errno.ENOENT or val.errno == errno.EPERM:  # either kernel thread or process is gone
            raise LookupError
        raise

    if split_args:
        return " ".join(cmdline)

    if path.endswith(" (deleted)"):
        path = path[:-10]

        if os.path.exists(path):
            path += " [updated]"
        else:
            # The path could be have pre-link stuff so try cmdline which might have the full path present.
            if os.path.exists(cmdline[0]):
                path = cmdline[0] + " [updated]"
            else:
                path += " [deleted]"
    exe = os.path.basename(path)
    cmd = proc.open(pid, 'status').readline()[6:-1]
    if exe.startswith(cmd):
        cmd = exe  # show non truncated version
    return cmd


def get_vm_info():
    TOTAL_MEM = 0
    TOTAL_CPUS = 0
    conn = libvirt.open("qemu:///system")
    for id in conn.listDomainsID():
        dom = conn.lookupByID(id)
        infos = dom.info()
        TOTAL_MEM += infos[1]
        TOTAL_CPUS += infos[3]
    return TOTAL_MEM, TOTAL_CPUS



def get_meminfo():
    total_mem = 0
    available_mem = 0

    for line in proc.open('/proc/meminfo').readlines():
        if re.split(' ', line)[0] == "MemTotal:":
            total_mem = re.split(' *', line)[1]
        if re.split(' ', line)[0] == "MemAvailable:":
            available_mem = re.split(' *', line)[1]
    return total_mem, available_mem


def get_cpu_affinity(pids_to_show, proc_names_to_show, cpus_to_show, split_args, include_self=True, only_self=False):
    tasks = {}

    for procpid in os.listdir(proc.path('')):
        if not procpid.isdigit():
            continue

        try:
            proccmd = get_cmd_name(procpid, split_args)
        except LookupError:
            continue

        for pid in os.listdir(proc.path(procpid, 'task')):
            if not pid.isdigit():
                continue

            pid = int(pid)

            if only_self and pid != our_pid:
                continue
            if pid == our_pid and not include_self:
                continue
            if pids_to_show is not None and pid not in pids_to_show:
                continue

            try:
                if os.path.exists(proc.path(procpid, 'task', pid, 'stat')):  # stat
                    for line in proc.open(procpid, 'task', pid, 'stat').readlines():
                        cpu = re.split('\(.*\)| ', line)[39]
                        if cpus_to_show is None or int(cpu) in cpus_to_show:
                            add = 1
                            cmd = get_cmd_name(pid, split_args)

                            if proc_names_to_show is not None:
                                add = 0
                                if cmd in proc_names_to_show or proccmd in proc_names_to_show:
                                    add = 1
                            if add == 1:
                                tasks[pid] = (cpu, cmd, proccmd)

            except LookupError:
                # kernel threads don't have exe links or process is gone
                continue
    return tasks


def verify_environment():
    if os.geteuid() != 0:
        sys.stderr.write("Root permission is required.\n")
        if __name__ == '__main__':
            sys.stderr.close()
            sys.exit(1)
    try:
        kv = kernel_ver()
    except (IOError, OSError):
        val = sys.exc_info()[1]
        if val.errno == errno.ENOENT:
            sys.stderr.write("Couldn't access " + proc.path('') + "\nOnly GNU/Linux is supported\n")
            sys.exit(2)
        else:
            raise


def std_exceptions(exception_type, value, tb):
    sys.excepthook = sys.__excepthook__
    if issubclass(exception_type, KeyboardInterrupt):
        pass
    elif issubclass(exception_type, IOError) and value.errno == errno.EPIPE:
        pass
    else:
        sys.__excepthook__(exception_type, value, tb)


def find_pids(process_names):
    include_self = True
    only_self = False
    pids = []
    for pid in os.listdir(proc.path('')):
        if not pid.isdigit():
            continue
        pid = int(pid)

        if only_self and pid != our_pid:
            continue
        if pid == our_pid and not include_self:
            continue
        if pids_to_show is not None and pid not in pids_to_show:
            continue

        try:
            cmd = get_cmd_name(pid, False)
            for name in process_names:
                if name == cmd:
                    pids.append(pid)
        except LookupError:
            # kernel threads don't have exe links or process is gone
            continue

    return pids


class KVMAllocDaemon(Daemon):
    def run(self):
        while True:
            kvmalloc_main(True)


def print_cpu_usage(tasks, last_tasks=None, sparse=False, daemonize=False, logfile=None, proc_names_to_show=None):
    sorted_tasks = [x for x in tasks.iteritems()]
    sorted_tasks.sort(key=lambda x: x[1][0])  # sort by cpu

    if sparse and last_tasks is not None:
        if last_tasks is not None:  # if this isn't the first time the process has been seen
            last_sorted_tasks = [x for x in last_tasks.iteritems()]
            last_sorted_tasks.sort(key=lambda x: x[1][0])  # sort by cpu
            new_tasks = set(sorted_tasks).difference(last_sorted_tasks)

            for newtask in new_tasks:
                if daemonize:
                    logfile.write(str(datetime.now()) + ": ")
                    logfile.write("%4s%s %9s %20s \t%s%s%s\n" % ("CPU-", newtask[1][0], newtask[0], newtask[1][1], "(", newtask[1][2], ")"))
                    logfile.flush()
                else:
                    sys.stdout.write(str(datetime.now()) + ": ")
                    sys.stdout.write("%4s%s %9s %20s \t%s%s%s\n" % ("CPU-", newtask[1][0], newtask[0], newtask[1][1], "(", newtask[1][2], ")"))

    else:
        for task in sorted_tasks:
            if daemonize:
                if sparse:
                    logfile.write(str(datetime.now()) + ": ")
                logfile.write("%4s%s %9s %20s \t%s%s%s\n" % ("CPU-", task[1][0], task[0], task[1][1], "(", task[1][2], ")"))
                logfile.flush()
            else:
                if sparse:
                    sys.stdout.write(str(datetime.now()) + ": ")
                sys.stdout.write("%4s%s %9s %20s \t%s%s%s\n" % ("CPU-", task[1][0], task[0], task[1][1], "(", task[1][2], ")"))


def kvmalloc_main(daemonize=False):
    logfile = None
    tasks = None

    daemon_cmd, logfile_location, split_args, pids_to_show, cpus_to_show, proc_names_to_show, \
        watch, only_total, verbose, sparse = parse_options()

    if proc_names_to_show is None:
        proc_names_to_show = ["qemu-kvm"]

    ncpu = multiprocessing.cpu_count()

    if daemonize:
        if logfile_location is None:
            logfile_location = "/var/log/kvmalloc.log"
        logfile = open(logfile_location, 'w')

    if watch is not None:
        try:
            while True:
                if not sparse:
                    timestamp = datetime.now()
                    if daemonize:
                        logfile.write("\n**** " + str(timestamp) + " ****\n\n")
                        logfile.flush()
                    else:
                        print "\n****", timestamp, "****\n"

                last_tasks = tasks

                tasks = get_cpu_affinity(pids_to_show, proc_names_to_show, cpus_to_show, split_args)

                if verbose:
                    print ""
                    print "Total %s threads: %s" % (proc_names_to_show[0], len(tasks))
                    print_cpu_usage(tasks, None, sparse, daemonize, logfile, proc_names_to_show)
                total_memory, available_memory = get_meminfo()
                total_vm_mem, total_vm_cpus = get_vm_info()
                print ""
                print "Total System Memory:", human(int(total_memory))
                print "Allocated VM Memory: %s" % (human(total_vm_mem))
                print "Available System Memory:", human(int(available_memory))
                print ""
                print "Physical CPUs: %s" % (ncpu)
                print "Allocated VM CPUs: %s" % (total_vm_cpus)
                print "VM CPU/Physical CPU ratio: %s" % (float(total_vm_cpus) / float(ncpu))
                print ""

                time.sleep(watch)  # milliseconds

        except KeyboardInterrupt:
            pass
    else:
        tasks = get_cpu_affinity(pids_to_show, proc_names_to_show, cpus_to_show, split_args)

        if verbose:
            print ""
            print "Total %s threads: %s" % (proc_names_to_show[0], len(tasks))
            print_cpu_usage(tasks, None, sparse, daemonize, logfile, proc_names_to_show)
        total_memory, available_memory = get_meminfo()
        total_vm_mem, total_vm_cpus = get_vm_info()
        print ""
        print "Total System Memory:", human(int(total_memory))
        print "Allocated VM Memory: %s" % (human(total_vm_mem))
        print "Available System Memory:", human(int(available_memory))
        print ""
        print "Physical CPUs: %s" % (ncpu)
        print "Allocated VM CPUs: %s" % (total_vm_cpus)
        print "VM CPU/Physical CPU ratio: %s" % (float(total_vm_cpus) / float(ncpu))
        print ""

    sys.stdout.close()
    if daemonize:
        logfile.close()


# Globals
sys.excepthook = std_exceptions
our_pid = os.getpid()
proc = Proc()


if __name__ == '__main__':
    daemon_cmd, logfile_location, split_args, pids_to_show, cpus_to_show, \
        proc_names_to_show, watch, only_total, verbose, sparse = parse_options()
    verify_environment()
    daemon = KVMAllocDaemon('/var/run/kvmalloc.pid')
    if daemon_cmd is not None:
        if daemon_cmd == 'start':
            print "kvmalloc daemon STARTED"
            daemon.start()
        elif daemon_cmd == 'stop':
            print "kvmalloc daemon STOPPED"
            daemon.stop()
        elif daemon_cmd == 'restart':
            print "kvmalloc daemon RESTARTED"
            daemon.restart()
    else:
        kvmalloc_main()