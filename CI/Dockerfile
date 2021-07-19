FROM kalilinux/kali:latest
RUN apt update && apt upgrade -y
RUN apt install -y less linux-exploit-suggester python3 python3-pip qemu-system-aarch64 qemu qemu-kvm virt-manager virt-viewer exploitdb
RUN which searchsploit
RUN which linux-exploit-suggester
RUN pip install pexpect
RUN mkdir /firmware
ADD firmware_check.py /
