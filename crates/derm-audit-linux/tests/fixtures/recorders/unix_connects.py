# The connects whose records the kernel writes: a pathname socket, an
# abstract one, and a pathname one with addrlen = sizeof(struct sockaddr_un).
import os, socket, struct, ctypes
try: os.unlink("/tmp/dsk")
except FileNotFoundError: pass
srv=socket.socket(socket.AF_UNIX); srv.bind("/tmp/dsk"); srv.listen(4)
a=socket.socket(socket.AF_UNIX); a.bind("\0dabs"); a.listen(4)
c=socket.socket(socket.AF_UNIX); c.connect("/tmp/dsk"); c.close()
c=socket.socket(socket.AF_UNIX); c.connect("\0dabs"); c.close()
libc=ctypes.CDLL(None, use_errno=True)
c=socket.socket(socket.AF_UNIX)
sun=struct.pack("=H108s",1,b"/tmp/dsk")
print("connect110", libc.connect(c.fileno(), ctypes.c_char_p(sun), 110))
c.close()
