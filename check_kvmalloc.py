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
        opts, args = getopt.getopt(sys.argv[1:], "hCMc:w:", long_options)
    except getopt.GetoptError:
        sys.stderr.write(display_help())
        sys.exit(3)

    if len(args):
        sys.stderr.write("Unknown arguments: %s\n" % args)
        sys.exit(3)

    mode = None
    warning = None
    critical = None
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
    cpu_ratio = 0
    mem_ratio = 0

    for o, a in opts:
        if o in ('-C'):
            mode = "CPU"
        if o in ('-M'):
            mode = "MEM"
        if o in ('-h', '--help'):
            sys.stdout.write(display_help())
            sys.exit(0)
        if o in ('-c',):
            try:
                critical = a
            except:
                sys.stderr.write(display_help())
                sys.exit(3)
        if o in ('-w',):
            try:
                warning = a
            except:
                sys.stderr.write(display_help())
                sys.exit(3)
    return mode, critical, warning


def display_help():
    help_msg = 'Usage: kvmalloc [OPTION]...\n' \
               '\n' \
               '  -h, -help                   Show this help\n' \
               '  -C                          Check CPU allocation\n' \
               '  -M                          Chck Memory allocation\n' \
               '  -c <value>                  Critical value\n\n'\
               '  -w <value>                  Warming value\n\n'
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
        try:
            cmd = get_cmd_name(pid, False)
            for name in process_names:
                if name == cmd:
                    pids.append(pid)
        except LookupError:
            # kernel threads don't have exe links or process is gone
            continue

    return pids


def kvmalloc_main(daemonize=False):
    logfile = None
    tasks = None
    status = "OK"

    mode, critical, warning = parse_options()
    proc_names_to_show = ["qemu-kvm"]
    ncpu = multiprocessing.cpu_count()

    total_memory, available_memory = get_meminfo()
    total_vm_mem, total_vm_cpus = get_vm_info()

    if mode == "MEM":
        mem_ratio = float(total_vm_mem) / float(total_memory) * 100
        if float(mem_ratio) >= float(critical):
            status = "Critical"
        elif float(mem_ratio) >= float(warning):
            status = "Warning"

        print mode, status, "-", "Mem Physical/VM/Util = %s/%s/%s %%|Util=%s;%s;%s;0" % (total_memory, total_vm_mem, mem_ratio, mem_ratio, warning, critical)

    if mode == "CPU":
        cpu_ratio = float(total_vm_cpus) / float(ncpu) * 100
        if float(cpu_ratio) >= float(critical):
            status = "Critical"
        elif float(cpu_ratio) >= float(warning):
            status = "Warning"

        print mode, status, "-", "CPU Physical/VM/Util = %s/%s/%s %%|Util=%s;%s;%s;0" % (ncpu, total_vm_cpus, cpu_ratio, cpu_ratio, warning, critical)

    sys.stdout.close()


# Globals
sys.excepthook = std_exceptions
our_pid = os.getpid()
proc = Proc()


if __name__ == '__main__':
    mode, critical, warning = parse_options()
    verify_environment()
    kvmalloc_main()
