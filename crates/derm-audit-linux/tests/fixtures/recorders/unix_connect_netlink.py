# Minimal audit netlink client: records the kernel's own SYSCALL and
# SOCKADDR records for AF_UNIX connects (lane PC, rules 9.12). Root only,
# cloud workspace only. Adds one exit rule for connect, prints each record
# as auditd's RAW format writes it ("type=<NAME> msg=<text>"), then removes
# the rule and turns audit off again.
import os, socket, struct, sys, time, threading
NETLINK_AUDIT=9
AUDIT_GET=1000; AUDIT_SET=1001; AUDIT_ADD_RULE=1011; AUDIT_DEL_RULE=1012
NAMES={1300:"SYSCALL",1306:"SOCKADDR",1320:"EOE",1302:"PATH",1307:"CWD",1327:"PROCTITLE"}
def nlmsg(t, payload, flags=0x5):
    return struct.pack("=IHHII", 16+len(payload), t, flags, 1, 0)+payload
def status(enabled, pid):
    # struct audit_status: mask, enabled, failure, pid, rate_limit,
    # backlog_limit, lost, backlog, feature_bitmap, backlog_wait_time,
    # backlog_wait_time_actual (include/uapi/linux/audit.h)
    return struct.pack("=11I", 1|4, enabled, 1, pid, 0, 0, 0, 0, 0, 0, 0)
def rule():
    key=b"derm_net"
    mask=[0]*64; mask[42//32]|=1<<(42%32)
    fields=[0]*64; values=[0]*64; flags=[0]*64
    fields[0]=11; values[0]=0xc000003e; flags[0]=0x40000000   # arch == x86_64
    fields[1]=210; values[1]=len(key); flags[1]=0x40000000    # filterkey
    body=struct.pack("=III",0x04,2,2)+struct.pack("=64I",*mask)+struct.pack("=64I",*fields)+struct.pack("=64I",*values)+struct.pack("=64I",*flags)+struct.pack("=I",len(key))+key
    return body
s=socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_AUDIT)
s.bind((0,0))
s.send(nlmsg(AUDIT_SET, status(1, os.getpid())))
s.send(nlmsg(AUDIT_ADD_RULE, rule()))
out=[]
stop=False
def reader():
    s.settimeout(0.5)
    while not stop:
        try: data=s.recv(65536)
        except socket.timeout: continue
        # kauditd sends one record per datagram; take the payload whole
        # (libaudit reads it the same way; nlmsg_len is not relied on).
        ln,t,fl,seq,pid=struct.unpack_from("=IHHII",data,0)
        payload=data[16:]
        if t>=1300:
            out.append("type=%s msg=%s"%(NAMES.get(t,"UNKNOWN[%d]"%t), payload.rstrip(b"\0").decode("latin1")))
        elif t==2:
            err=struct.unpack_from("=i",payload,0)[0]
            if err: out.append("# netlink error %d"%err)
th=threading.Thread(target=reader); th.start()
time.sleep(0.5)
# The connects: a pathname socket, an abstract one, and a pathname one with
# addrlen = sizeof(struct sockaddr_un) (110), as C programs often pass.
import subprocess
subprocess.run([sys.executable,"-I",os.path.join(os.path.dirname(os.path.abspath(__file__)),"unix_connects.py")])
time.sleep(1.5)
stop=True; th.join()
s.send(nlmsg(AUDIT_DEL_RULE, rule()))
s.send(nlmsg(AUDIT_SET, status(0, 0)))
time.sleep(0.2)
print("\n".join(out))
