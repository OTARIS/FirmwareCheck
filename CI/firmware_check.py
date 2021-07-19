#!/bin/python3
import os, time, sys, subprocess
import re, pexpect

ALLOWED_PORTS = None

class Service:
    def __init__(self, name, cmd, version_switch='--version'):
        self.name = name
        self.cmd = cmd
        self.version_switch = version_switch
        self.version = ""

    def print_version(self):
        if self.version is not None:
            log(f"{self.name}: {self.version}")

SERVICES = [
    Service('Apache', 'apache2'),
    Service('Nginx', 'nginx', '-v'),
    Service('Lighttpd', 'lighttpd'),
    Service('MySQL', 'mysql'),
    Service('MongoDB', 'mongo'),
    Service('PostgreSQL', 'postgres'),
    Service('SQLite', 'sqlite'),
    Service('Dropbear', 'dropbear'),
    Service('SSH', 'sshd'),
    Service('FTP', 'ftpd'),
    Service('VSFTPD', 'vsftpd', '-v'),
    Service('Memcached', 'memcached'),
    Service('Redis', 'redis'),
    Service('Mosquitto', 'mosquitto', '-v')
]

USEFUL_BINARIES = ["socat", "nc", "netcat", "curl", "wget", "ssh", "dropbear", "gcc", "python", "python3", "perl", "ruby", "javac"]

target = {
    'KERNEL_VERSION': None,
    'OPEN_PORTS': []
}

class colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def section(msg):
    print(f"\n{colors.OKGREEN}-->{colors.ENDC} {msg}")

def log(msg):
    print(f"    {msg}")

def log_positive(msg):
    print(f"{colors.OKGREEN}[+]{colors.ENDC} {msg}")

def log_header(msg):
    print(f"\n{colors.OKBLUE}-->{colors.ENDC} {msg}")

def log_warning(msg):
    print(f"{colors.WARNING}[!]{colors.ENDC} {msg}")

def escape_ansi(line):
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)

def get_emulation_process():
    child = pexpect.spawn(command='./firmware/start-qemu.sh', timeout=1000)
    child.expect('buildroot login: ')
    child.sendline('root')
    child.expect('# ')
    return child

def exec_cmd(process, cmd):
    process.sendline(f"""sh -c "{cmd}" """)
    process.expect('# ')
    output = [s.replace('\r\r','') for s in process.before.decode().split('\n')[1:]]
    return '\n'.join([s for s in output if s != ''])

def get_version(process, service: Service):
    if exec_cmd(process, f'which {service.cmd}'):
        version_string = exec_cmd(process, f'{service.cmd} {service.version_switch}')
        version = re.findall(r'(?:(\d+\.(?:\d+\.)*\d+))', version_string)
        return version[0]
    else:
        return None

def search_files_for_pattern(process, files, regex):
    for file in files:
        exec_cmd(process, f"grep -E '{regex}' {file}")


def filter_processes(proc):
    ignore_list = [']', 'grep root', 'ps aux', '-sh', 'init', 'syslogd -n', 'klogd -n']
    for s in ignore_list:
        if proc.endswith(s):
            return False
    return True

def main():
    print("""┌─┐┬┬─┐┌┬┐┬ ┬┌─┐┬─┐┌─┐  ┌─┐┬ ┬┌─┐┌─┐┬┌─
├┤ │├┬┘││││││├─┤├┬┘├┤   │  ├─┤├┤ │  ├┴┐
└  ┴┴└─┴ ┴└┴┘┴ ┴┴└─└─┘  └─┘┴ ┴└─┘└─┘┴ ┴
""")
    log_header("Starting emulation of firmware...")
    p = get_emulation_process()
    time.sleep(5) # wait a while for some processes to start

    log_positive(f"Emulating '{exec_cmd(p, 'uname -a')}'")
    target['KERNEL_VERSION'] = exec_cmd(p, "uname -r | awk -F'-' '{ print $1 }'")

    log_header("Checking service versions")
    for service in SERVICES:
        service.version = get_version(p, service)
        service.print_version()

    log_header("Checking for default passwords")
    if exec_cmd(p, f'which mysql'):
        if exec_cmd(p, "mysqladmin -u root version 2>/dev/null"):
            log_warning("MySQL allows login without password")
            exec_cmd(p, "mysql -u root -e 'SELECT User,Host,authentication_string FROM mysql.user;' 2>/dev/null")
        else:
            log_positive("Root login without password not allowed")
    debian_conf = exec_cmd(p, 'find $d -name debian.cnf 2>/dev/null')
    for f in debian_conf:
        exec_cmd(p, f"cat {f} | grep -i passw -A 1 -B 1 | while read -r line; do log '$line'; done")
    log_positive("No readable debian.cnf found containing MySQL-Passwords")

    log_header("Looking for leftover ssh files")
    ssh_files = exec_cmd(p, "find / -name 'id_rsa*' 2>/dev/null")
    if not ssh_files:
        log_positive("No ssh files found")

    log_header("Looking for open ports")
    open_ports = exec_cmd(p, 'netstat -ntlup | grep -i listen | grep -v "127.0.0.1" 2>/dev/null')
    if not open_ports: # if -p option is not available TODO also look for ss
        open_ports = exec_cmd(p, 'netstat -ntlu | grep -i listen | grep -v "127.0.0.1"')
    for line in open_ports.split('\n'):
        port_number = re.findall(r':[0-9]+', line)
        if port_number:
            port = port_number[-1][1:]
            if port not in target['OPEN_PORTS']:
                target['OPEN_PORTS'].append(port)
        log(line)

    log_header('Processes running as root')
    found = False
    processes = exec_cmd(p, "ps aux | grep root")
    for proc in processes.split('\n'):
        if filter_processes(proc):
            found = True
            log(proc)
    if found:
        log_warning("Consider creating users for these processes if possible")
    else:
        log_positive("No unusual processes found running as root")

    log_header("Looking for binaries that can be useful for hackers")
    found = False
    for bin in USEFUL_BINARIES:
        bin_path = exec_cmd(p, f'which {bin}')
        if bin_path:
            log(f"{bin}: {bin_path}")
            found = True
    if found:
        log_warning("Consider removing these if they are not necessary")
    else:
        log_positive("None found")


    # ----------- End of firmware analysis
    p.close(force=True)

    section("Finished dynamic analysis & stopped firmware emulation")

    log_header("Checking CVEs for installed services")
    os.environ["TERM"] = "xterm"
    for service in SERVICES:
        if service.version:
            output = None
            try:
                print(f"Looking up CVEs for {service.name} {service.version}...")
                cmd = f"searchsploit -o {service.name} {service.version} | awk -F'|' "+"'{ print $1 }'"+f" | grep -i {service.name}"
                ps = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
                output = ps.communicate()[0].decode()
                output = escape_ansi(output)
            except:
                print(f"{service.name} {service.version} threw an error")
                pass

            if output:
                print(output)

    log_header(f"Looking for kernel exploits for kernel {target['KERNEL_VERSION']}...")
    try:
        print(subprocess.check_output(f"/usr/share/linux-exploit-suggester/linux-exploit-suggester.sh -k {target['KERNEL_VERSION']}", shell=True).decode())
    except:
        pass
    # ----------- End of CVE section

    section("Done\n")

    # ----------- Results
    found = False
    if ALLOWED_PORTS:
        for port in target['OPEN_PORTS']:
            if port not in ALLOWED_PORTS:
                log_warning(f"Port {port} open, even though it should not be!")
                found = True
    if found:
        print("")
        log_warning("Pipeline failed due to open ports")
        sys.exit(1)

def print_usage():
    print("Usage: firmware_check.py [--ports X,Y,Z]")
    print("")
    print("--ports X,Y,Z    Ports that are allowed to be open")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        main()
    elif len(sys.argv) > 1:
        if sys.argv[1] == '--ports':
            try:
                ALLOWED_PORTS = [port for port in sys.argv[2].split(',')]
            except:
                print_usage()
                sys.exit(1)
            main()
