#!/bin/sh

INSTALLED_SERVICES=""
SERVICE_VERSIONS=""

C=$(printf '\033')
RED="${C}[0;31m"
GREEN="${C}[1;32m"
YELLOW="${C}[1;33m"
BLUE="${C}[1;34m"
GREY="${C}[0;90m"
WHITE="${C}[1;37m"
NC="${C}[0m" # No Colour

banner() {
  echo -n $WHITE
  echo '┌─┐┬┬─┐┌┬┐┬ ┬┌─┐┬─┐┌─┐  ┌─┐┬ ┬┌─┐┌─┐┬┌─'
  echo '├┤ │├┬┘││││││├─┤├┬┘├┤   │  ├─┤├┤ │  ├┴┐'
  echo '└  ┴┴└─┴ ┴└┴┘┴ ┴┴└─└─┘  └─┘┴ ┴└─┘└─┘┴ ┴'
  echo -n $NC
}

nl() {
  echo "" # for busbybox-ash compatible newlines
}

heading() { nl && echo -n "${WHITE}>>> ${1}${NC}" && nl; }
subheading() { echo "${WHITE}> ${NC}${1}"; }
log_grey() { echo -n "${GREY}${1}$NC"; }
log_b() { echo -n "${BLUE}${1}${NC}"; }
log_g() { echo "${GREEN}[+]${NC} ${1}"; }
log_y() { echo "${YELLOW}[!]${NC} ${1}"; }
log_r() { echo "${RED}[-]${NC} ${1}"; }
log() { echo "    ${1}"; }

check_version() {
  if [ $(which $2) ]; then
    echo -n "$1: "
    VERSION=$($2 $3 0>&1 2>&1)
    VERSION=$(echo $VERSION | grep -Eo '[0-9\*.]+' | head -1)
    log_b "$VERSION" && nl
    INSTALLED_SERVICES="$INSTALLED_SERVICES $1"
    SERVICE_VERSIONS="$SERVICE_VERSIONS $VERSION"
  fi
}

check_existence() {
  if [ "$(which $1)" ]; then
    echo -n "$1: "
    log_b "$(which $1)" && nl
    return 0
  else
    return 1
  fi
}

output_to_yaml() {
  echo "    $1" >> fc_output.yaml
}

# =====================================
banner
echo "FirmwareCheck:" > fc_output.yaml

# general info
echo "Running on: " && log_grey "$(uname -a)"
KERNEL_VERSION=$(uname -r | awk -F'-' '{ print $1 }')
output_to_yaml "Kernel: ${KERNEL_VERSION}"
nl

heading "Looking for useful binaries"
BINARIES="socat nc netcat curl wget php xterm telnet gcc python python3 perl ruby"
FOUND_BINARIES=""
for BIN in $BINARIES; do
  check_existence $BIN && FOUND_BINARIES="${FOUND_BINARIES} $BIN"
done
if [ "$FOUND_BINARIES" ]; then
  output_to_yaml "Useful_Binaries:"
  for BIN in $FOUND_BINARIES; do
    output_to_yaml "- $(which $BIN)"
  done
fi

heading "Checking versions"
check_version Apache apache2 -v
check_version Nginx nginx -v
check_version Lighttpd lighttpd --version
check_version MySQL mysql --version
check_version MongoDB mongo --version
check_version PostgreSQL postgres --version
check_version SQLite sqlite --version
check_version Dropbear dropbear --version
check_version SSH sshd --version
check_version FTP ftpd --version
check_version vsFTP vsftpd -v
check_version Memcached memcached --version
check_version Redis redis --version
check_version Mosquitto mosquitto -v
output_to_yaml "Services:$INSTALLED_SERVICES"
output_to_yaml "Versions:$SERVICE_VERSIONS"

# default passwords:
# ---------------------------------------------------
## mysql
if [ "$(which mysql)" ]; then
  heading "Enumerating MySQL"
  if [ "$(mysqladmin -uroot version 2>/dev/null)" ]; then
    log_r "MySQL allows login without password"
    mysql -u root -e "SELECT User,Host,authentication_string FROM mysql.user;" 2>/dev/null
    output_to_yaml "MySQL_pwless-root: true"
  else
    log_g "Root login without password not allowed"
    output_to_yaml "MySQL_pwless-root: false"
  fi

  DEBIAN_CONF=$(find $d -name debian.cnf 2>/dev/null)
  FOUND_CONF=0
  for f in $DEBIAN_CONF; do
    if [ -r $f ]; then
      log_r "Found passwords in debian.cnf:"
      cat $DEBIAN_CONF | grep -i passw -A 1 -B 1 | while read -r line; do log "$line"; done
      FOUND_CONF=1
    fi
  done
  [ $FOUND_CONF ] || log_g "No readable debian.cnf found containing MySQL-Passwords"
fi

heading "Looking for ssh files"
SSH_FILES=$(find / -name 'id_rsa*' 2>/dev/null)
if [ $SSH_FILES ]; then
  echo $SSH_FILES
  output_to_yaml "SSH_files: $SSH_FILES"
fi

heading "Open ports"
[ "$(which netstat)" ] && NETSTAT=netstat
[ "$(which ss)" ] && NETSTAT=ss
if [ $NETSTAT ]; then
  $NETSTAT -ntaup | grep -i listen | grep -v '127.0.0.1' || log_g "No applications listening on 0.0.0.0:*"
  PORTS=$($NETSTAT -ntaup | grep -i listen  | grep -v '127.0.0.1' | base64 --wrap=0)
  output_to_yaml "OpenPorts: >"
  output_to_yaml "    $PORTS"
else
  log_r "netstat/ss not installed, could not check for ports"
fi

heading "Processes running as root"
ps aux | grep -i root | grep -vE 'grep|ps aux|\[*\]'
PROCESSES=$(ps auxc | grep root | grep -vE 'grep|firmware_check_|bash|sh|ps|\[*\]|awk|base64' | awk '{ print $11 }' | base64 --wrap=0)
output_to_yaml "RunningAsRoot: >"
output_to_yaml "    $PROCESSES"

heading "Looking for serial ports"
[ "$(cat /proc/tty/driver/serial  | grep -vE 'unknown|revision')" ] && echo "[!] Serial connection open"
SERIALS=$(cat /proc/tty/driver/serial  | grep -vE 'unknown|revision' | base64)
output_to_yaml "SerialPorts: >"
output_to_yaml "    $SERIALS"

heading "Finished. Output written to fc_output.yaml"
