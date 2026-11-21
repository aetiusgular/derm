# Lane PC: does a `-F dir=<store>` open rule fire for a read through a link
# that sits outside the store, and which name does the PATH record carry?
# Root, cloud workspace only; the rule is removed and audit set off after.
import os, socket, struct, sys, time, threading, subprocess, shutil
NETLINK_AUDIT=9; AUDIT_SET=1001; AUDIT_ADD_RULE=1011; AUDIT_DEL_RULE=1012
NAMES={1300:"SYSCALL",1302:"PATH",1307:"CWD",1320:"EOE",1327:"PROCTITLE"}
def nlmsg(t,p): return struct.pack("=IHHII",16+len(p),t,5,1,0)+p
def status(en,pid): return struct.pack("=11I",1|4,en,1,pid,0,0,0,0,0,0,0)
def rule(d):
    key=b"derm_sens"; dirb=d.encode()
    mask=[0]*64
    for n in (2,257): mask[n//32]|=1<<(n%32)   # open, openat (x86_64)
    f=[0]*64; v=[0]*64; fl=[0]*64
    f[0]=11; v[0]=0xc000003e; fl[0]=0x40000000
    f[1]=107; v[1]=len(dirb); fl[1]=0x40000000   # AUDIT_DIR
    f[2]=210; v[2]=len(key); fl[2]=0x40000000    # AUDIT_FILTERKEY
    buf=dirb+key
    return struct.pack("=III",0x04,2,3)+b"".join(struct.pack("=64I",*x) for x in (mask,f,v,fl))+struct.pack("=I",len(buf))+buf
root="/tmp/pcdir"; shutil.rmtree(root,ignore_errors=True)
os.makedirs(root+"/signin/codex"); os.makedirs(root+"/home/.codex")
open(root+"/signin/codex/auth.json","w").write("{}\n")
os.symlink(root+"/signin/codex/auth.json", root+"/home/.codex/auth.json")
s=socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,NETLINK_AUDIT); s.bind((0,0))
s.send(nlmsg(AUDIT_SET,status(1,os.getpid()))); s.send(nlmsg(AUDIT_ADD_RULE,rule(root+"/signin")))
out=[]; stop=False
def rd():
    s.settimeout(0.5)
    while not stop:
        try: data=s.recv(65536)
        except socket.timeout: continue
        t=struct.unpack_from("=IHHII",data,0)[1]
        if t>=1300: out.append("type=%s msg=%s"%(NAMES.get(t,"UNKNOWN[%d]"%t),data[16:].rstrip(b"\0").decode("latin1")))
        elif t==2:
            e=struct.unpack_from("=i",data,16)[0]
            if e: out.append("# netlink error %d"%e)
th=threading.Thread(target=rd); th.start(); time.sleep(0.5)
subprocess.run(["/bin/cat", root+"/home/.codex/auth.json"], stdout=subprocess.DEVNULL)
subprocess.run(["/bin/cat", root+"/signin/codex/auth.json"], stdout=subprocess.DEVNULL)
time.sleep(1.5); stop=True; th.join()
s.send(nlmsg(AUDIT_DEL_RULE,rule(root+"/signin"))); s.send(nlmsg(AUDIT_SET,status(0,0))); time.sleep(0.2)
print("\n".join(l for l in out if "comm=\"cat\"" in l or "type=PATH" in l or "type=CWD" in l or "error" in l))
