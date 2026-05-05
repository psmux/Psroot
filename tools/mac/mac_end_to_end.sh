#!/usr/bin/env bash
# Mac/Lima end-to-end proof for psroot. Run inside the lima `psroot` VM.
set -uo pipefail
PS=/workspace/Psroot/target/release/psroot
ROOTFS=/opt/psroot/rootfs
KEY=/root/ctr_ed25519

echo "########################################"
echo "# psroot Mac/Lima end-to-end proof     #"
echo "########################################"
date
echo "VM kernel: $(uname -a)"
echo "VM distro: $(grep PRETTY_NAME /etc/os-release)"

echo
echo "############### STEP 0: container ssh key ###############"
sudo test -f "$KEY" || sudo ssh-keygen -t ed25519 -N "" -f "$KEY" -q
sudo mkdir -p "$ROOTFS/root/.ssh"
sudo cp "${KEY}.pub" "$ROOTFS/root/.ssh/authorized_keys"
sudo chmod 700 "$ROOTFS/root/.ssh"
sudo chmod 600 "$ROOTFS/root/.ssh/authorized_keys"
sudo chown -R 0:0 "$ROOTFS/root/.ssh"
# Make sure sshd will start: generate host keys
sudo chroot "$ROOTFS" /bin/bash -c "test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A" 2>/dev/null || true
# Set root password to empty + permit root login
sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' "$ROOTFS/etc/ssh/sshd_config"
sudo mkdir -p "$ROOTFS/run/sshd"
sudo chmod 0755 "$ROOTFS/run/sshd"

echo
echo "############### STEP 1: clean state ###############"
sudo pkill -9 -f 'target/release/psroot run' 2>/dev/null
sudo rm -rf /root/.local/share/psroot ~/.local/share/psroot
sleep 1

echo
echo "############### STEP 2: launch container ###############"
sudo nohup "$PS" run --rootfs "$ROOTFS" --network outbound \
  --publish-addr 0.0.0.0 --publish 2222:22 \
  --memory 2G --max-procs 500 --name mac \
  -- /usr/sbin/sshd -D -e > /tmp/mac.log 2>&1 < /dev/null &
disown
sleep 5
sudo pgrep -af "psroot run" | head -2
echo "--- /tmp/mac.log ---"
sudo cat /tmp/mac.log

echo
echo "--- bridge psroot0 ---"
ip -br a show psroot0 2>&1
echo "--- iptables NAT ---"
sudo iptables -t nat -S | grep psroot | head -10
echo "--- container.json ---"
sudo find /root/.local/share/psroot/containers -name container.json 2>/dev/null | head -1 | xargs sudo cat 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print("container_ip:", d.get("network",{}).get("ip")); print("hostname:", d.get("hostname")); print("ports:", d.get("network",{}).get("ports"))' 2>/dev/null || echo "(no container.json yet)"

SSHC="ssh -i $KEY -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=5 -p 2222 root@127.0.0.1"

echo
echo "############### STEP 3: ssh INTO container (FROM the VM) ###############"
sudo $SSHC 'echo HELLO from inside the container; echo "uname:"; uname -a; echo "id:"; id; echo "hostname: $(hostname)"; echo "os-release:"; grep PRETTY_NAME /etc/os-release; echo "ip addr:"; ip -br addr; echo "default route:"; ip route'

echo
echo "############### STEP 4: process isolation ###############"
echo "VM processes: $(ps -ef | wc -l)"
echo "INSIDE container ps -ef:"
sudo $SSHC 'ps -ef'

echo
echo "############### STEP 5: filesystem isolation ###############"
echo "VM /workspace/Psroot listing (host-mounted):"
ls /workspace/Psroot | head -5
echo
echo "INSIDE container, /workspace exists?"
sudo $SSHC 'ls /workspace 2>&1; echo ---; ls /home; echo ---; ls /root'
echo
echo "INSIDE container, attempt to read VM secret /root/ctr_ed25519:"
sudo $SSHC 'cat /root/ctr_ed25519 2>&1 | head -2'
echo "(must say: No such file or directory)"

echo
echo "############### STEP 6: outbound network ###############"
sudo $SSHC 'getent ahosts archive.ubuntu.com | head -1; echo HTTPS:; curl -sS -o /dev/null -w "kernel.org -> %{http_code}\n" https://www.kernel.org/; curl -sS -o /dev/null -w "github.com -> %{http_code}\n" https://api.github.com/'

echo
echo "############### STEP 7: apt + node + python INSIDE ###############"
sudo $SSHC 'export DEBIAN_FRONTEND=noninteractive; apt-get update >/dev/null 2>&1 && echo apt update OK; apt-get install -y --no-install-recommends nodejs npm python3-pip python3-venv >/dev/null 2>&1 && echo apt install OK; echo node $(node --version); echo npm $(npm --version); echo $(python3 --version); echo $(pip --version 2>/dev/null || pip3 --version)'

echo
echo "############### STEP 8: Node HTTP server ###############"
sudo $SSHC 'cat > /tmp/srv.js <<EOF
const http=require("http");
http.createServer((q,s)=>{s.writeHead(200);s.end("hello-from-node-on-mac\n");}).listen(8080,"0.0.0.0");
EOF
nohup node /tmp/srv.js > /tmp/srv.log 2>&1 &
sleep 2
curl -sS http://127.0.0.1:8080/'

echo
echo "############### STEP 9: Flask ###############"
sudo $SSHC 'python3 -m venv /tmp/venv >/dev/null 2>&1
/tmp/venv/bin/pip install flask -q
cat > /tmp/app.py <<EOF
from flask import Flask
a=Flask(__name__)
@a.route("/")
def i(): return "hello-from-flask-on-mac\n"
a.run("0.0.0.0", 8081)
EOF
nohup /tmp/venv/bin/python3 /tmp/app.py > /tmp/flask.log 2>&1 &
sleep 3
curl -sS http://127.0.0.1:8081/'

echo
echo "############### STEP 10: Django ###############"
sudo $SSHC '/tmp/venv/bin/pip install django -q
mkdir -p /tmp/djroot && cd /tmp/djroot
/tmp/venv/bin/django-admin startproject djapp 2>/dev/null
cd djapp
nohup /tmp/venv/bin/python3 manage.py runserver 0.0.0.0:8000 > /tmp/dj.log 2>&1 &
sleep 5
curl -sS -o /tmp/dj.html -w "django http %{http_code} size=%{size_download}\n" http://127.0.0.1:8000/
grep -o "<title>[^<]*</title>" /tmp/dj.html'

echo
echo "############### STEP 11: re-confirm isolation ###############"
echo "container PIDs: $(sudo $SSHC "ps -e --no-headers | wc -l")"
echo "VM PIDs: $(ps -e --no-headers | wc -l)"
echo "container hostname: $(sudo $SSHC hostname)"
echo "VM hostname: $(hostname)"

echo
echo "############### STEP 12: container list ###############"
sudo "$PS" ls

echo
echo "############### ALL DONE ###############"
date
