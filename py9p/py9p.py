# Copyright (c) 2008-2011 Tim Newsham, Andrey Mirtchovski
# Copyright (c) 2011-2012 Peter V. Saveliev
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""
9P protocol implementation as documented in plan9 intro(5) and <fcall.h>.
"""

import os
import stat
import sys
import socket
import select
import traceback
import io
import threading
import struct

if sys.version_info[0] == 2:
    def bytes3(x):
        if isinstance(x, unicode):
            return bytes(x.encode('utf-8'))
        else:
            return bytes(x)
else:
    unicode = str
    def bytes3(x):
        return bytes(x, 'utf-8')

IOHDRSZ = 24
PORT = 564

cmdName = {}


Tversion = 100
Rversion = 101
Tauth = 102
Rauth = 103
Tattach = 104
Rattach = 105
Terror = 106
Rerror = 107
Tflush = 108
Rflush = 109
Twalk = 110
Rwalk = 111
Topen = 112
Ropen = 113
Tcreate = 114
Rcreate = 115
Tread = 116
Rread = 117
Twrite = 118
Rwrite = 119
Tclunk = 120
Rclunk = 121
Tremove = 122
Rremove = 123
Tstat = 124
Rstat = 125
Twstat = 126
Rwstat = 127

for i, k in dict(globals()).items():
    try:
        if (i[0] in ('T', 'R')) and isinstance(k, int):
            cmdName[k] = i
    except:
        pass

version = b'9P2000'
versionu = b'9P2000.u'

Ebadoffset = "bad offset"
Ebotch = "9P protocol botch"
Ecreatenondir = "create in non-directory"
Edupfid = "duplicate fid"
Eduptag = "duplicate tag"
Eisdir = "is a directory"
Enocreate = "create prohibited"
Enoremove = "remove prohibited"
Enostat = "stat prohibited"
Enotfound = "file not found"
Enowstat = "wstat prohibited"
Eperm = "permission denied"
Eunknownfid = "unknown fid"
Ebaddir = "bad directory in wstat"
Ewalknotdir = "walk in non-directory"
Eopen = "file not open"

NOTAG = 0xffff
NOFID = 0xffffffff

# for completeness including all of p9p's defines
OREAD = 0         # open for read
OWRITE = 1        # write
ORDWR = 2         # read and write
OEXEC = 3         # execute, == read but check execute permission
OTRUNC = 16       # or'ed in (except for exec), truncate file first
OCEXEC = 32       # or'ed in, close on exec
ORCLOSE = 64      # or'ed in, remove on close
ODIRECT = 128     # or'ed in, direct access
ONONBLOCK = 256   # or'ed in, non-blocking call
OEXCL = 0x1000    # or'ed in, exclusive use (create only)
OLOCK = 0x2000    # or'ed in, lock after opening
OAPPEND = 0x4000  # or'ed in, append only

AEXIST = 0        # accessible: exists
AEXEC = 1         # execute access
AWRITE = 2        # write access
AREAD = 4         # read access

# Qid.type
QTDIR = 0x80      # type bit for directories
QTAPPEND = 0x40   # type bit for append only files
QTEXCL = 0x20     # type bit for exclusive use files
QTMOUNT = 0x10    # type bit for mounted channel
QTAUTH = 0x08     # type bit for authentication file
QTTMP = 0x04      # type bit for non-backed-up file
QTSYMLINK = 0x02  # type bit for symbolic link
QTFILE = 0x00     # type bits for plain file

# Dir.mode
DMDIR = 0x80000000        # mode bit for directories
DMAPPEND = 0x40000000     # mode bit for append only files
DMEXCL = 0x20000000       # mode bit for exclusive use files
DMMOUNT = 0x10000000      # mode bit for mounted channel
DMAUTH = 0x08000000       # mode bit for authentication file
DMTMP = 0x04000000        # mode bit for non-backed-up file
DMSYMLINK = 0x02000000    # mode bit for symbolic link (Unix, 9P2000.u)
DMDEVICE = 0x00800000     # mode bit for device file (Unix, 9P2000.u)
DMNAMEDPIPE = 0x00200000  # mode bit for named pipe (Unix, 9P2000.u)
DMSOCKET = 0x00100000     # mode bit for socket (Unix, 9P2000.u)
DMSETUID = 0x00080000     # mode bit for setuid (Unix, 9P2000.u)
DMSETGID = 0x00040000     # mode bit for setgid (Unix, 9P2000.u)
DMSTICKY = 0x00010000     # mode bit for sticky bit (Unix, 9P2000.u)

DMREAD = 0x4     # mode bit for read permission
DMWRITE = 0x2    # mode bit for write permission
DMEXEC = 0x1     # mode bit for execute permission

ERRUNDEF = 0xFFFFFFFF
UIDUNDEF = 0xFFFFFFFF

# supported authentication protocols
auths = ['pki', 'sk1']


class Error(Exception):
    pass


class EofError(Error):
    pass


class EdupfidError(Error):
    pass


class RpcError(Error):
    pass


class ServerError(Error):
    pass


class ClientError(Error):
    pass


class VersionError(Error):
    pass


class Marshal9P(object):
    chatty = False

    @property
    def length(self):
        p = self.buf.tell()
        self.buf.seek(0, 2)
        l = self.buf.tell()
        self.buf.seek(p)
        return l

    def enc1(self, x):
        """Encode 1-byte unsigned"""
        self.buf.write(struct.pack('B', x))

    def dec1(self):
        """Decode 1-byte unsigned"""
        return struct.unpack('b', self.buf.read(1))[0]

    def enc2(self, x):
        """Encode 2-byte unsigned"""
        self.buf.write(struct.pack('H', x))

    def dec2(self):
        """Decode 2-byte unsigned"""
        return struct.unpack('H', self.buf.read(2))[0]

    def enc4(self, x):
        """Encode 4-byte unsigned"""
        self.buf.write(struct.pack('I', x))

    def dec4(self):
        """Decode 4-byte unsigned"""
        return struct.unpack('I', self.buf.read(4))[0]

    def enc8(self, x):
        """Encode 8-byte unsigned"""
        self.buf.write(struct.pack('Q', x))

    def dec8(self):
        """Decode 8-byte unsigned"""
        return struct.unpack('Q', self.buf.read(8))[0]

    def encS(self, x):
        """Encode data string with 2-byte length"""
        self.buf.write(struct.pack("H", len(x)))
        if isinstance(x, str) or isinstance(x, unicode):
            x = bytes3(x)
        self.buf.write(x)

    def decS(self):
        """Decode data string with 2-byte length"""
        return self.buf.read(self.dec2())

    def encD(self, d):
        """Encode data string with 4-byte length"""
        self.buf.write(struct.pack("I", len(d)))
        if isinstance(d, str) or isinstance(d, unicode):
            d = bytes3(d)
        self.buf.write(d)

    def decD(self):
        """Decode data string with 4-byte length"""
        return self.buf.read(self.dec4())

    def encF(self, *argv):
        """Encode data directly by struct.pack"""
        self.buf.write(struct.pack(*argv))

    def decF(self, fmt, length):
        """Decode data by struct.unpack"""
        return struct.unpack(fmt, self.buf.read(length))

    def encQ(self, q):
        """Encode Qid structure"""
        self.encF("=BIQ", q.type, q.vers, q.path)

    def decQ(self):
        """Decode Qid structure"""
        return Qid(self.dec1(), self.dec4(), self.dec8())

    def __init__(self, dotu=0, chatty=False):
        self.chatty = chatty
        self.dotu = dotu
        self._lock = threading.Lock()
        self.buf = None

    def _checkType(self, t):
        if t not in cmdName:
            raise Error("Invalid message type %d" % t)

    def _checkSize(self, v, mask):
        if v != v & mask:
            raise Error("Invalid value %d" % v)

    def _checkLen(self, x, l):
        if len(x) != l:
            raise Error("Wrong length %d, expected %d: %r" % (
                len(x), l, x))

    def setBuffer(self, init=b""):
        self.buf = io.BytesIO()
        self.buf.write(init)

    def send(self, fd, fcall):
        "Format and send a message"
        with self._lock:
            self.setBuffer(b"0000")
            self._checkType(fcall.type)
            if self.chatty:
                print("-%d-> %s %s %s" % (fd.fileno(), cmdName[fcall.type], \
                    fcall.tag, fcall.tostr()))
            self.enc(fcall)
            self.buf.seek(0)
            self.enc4(self.length)
            fd.write(self.buf.getvalue())

    def recv(self, fd):
        "Read and decode a message"
        with self._lock:
            size = struct.unpack("I", fd.read(4))[0]
            if size > 0xffffffff or size < 7:
                raise Error("Bad message size: %d" % size)
            self.setBuffer(fd.read(size - 4))
            self.buf.seek(0)
            mtype, tag = self.decF("=BH", 3)
            self._checkType(mtype)
            fcall = Fcall(mtype, tag)
            self.dec(fcall)
            # self._checkResid() -- FIXME: check the message residue
            if self.chatty:
                print("<-%d- %s %s %s" % (fd.fileno(), cmdName[mtype],
                        tag, fcall.tostr()))
            return fcall

    def encstat(self, stats, enclen=1):
        statsz = 0
        for x in stats:
            if self.dotu:
                x.statsz = 61 + \
                        len(x.name) + len(x.uid) + len(x.gid) + \
                        len(x.muid) + len(x.extension)
                statsz += x.statsz
            else:
                x.statsz = 47 + \
                        len(x.name) + len(x.uid) + len(x.gid) + \
                        len(x.muid)
                statsz += x.statsz
        if enclen:
            self.enc2(statsz + 2)

        for x in stats:
            self.encF("=HHIBIQIIIQ",
                    x.statsz, x.type, x.dev, x.qid.type, x.qid.vers,
                    x.qid.path, x.mode, x.atime, x.mtime, x.length)
            self.encS(x.name)
            self.encS(x.uid)
            self.encS(x.gid)
            self.encS(x.muid)
            if self.dotu:
                self.encS(x.extension)
                self.encF("=III",
                        x.uidnum, x.gidnum, x.muidnum)

    def enc(self, fcall):
        self.encF("=BH", fcall.type, fcall.tag)
        if fcall.type in (Tversion, Rversion):
            self.encF("I", fcall.msize)
            self.encS(fcall.version)
        elif fcall.type == Tauth:
            self.encF("I", fcall.afid)
            self.encS(fcall.uname)
            self.encS(fcall.aname)
            if self.dotu:
                self.encF("I", fcall.uidnum)
        elif fcall.type == Rauth:
            self.encQ(fcall.aqid)
        elif fcall.type == Rerror:
            self.encS(fcall.ename)
            if self.dotu:
                self.encF("I", fcall.errno)
        elif fcall.type == Tflush:
            self.encF("H", fcall.oldtag)
        elif fcall.type == Tattach:
            self.encF("=II", fcall.fid, fcall.afid)
            self.encS(fcall.uname)
            self.encS(fcall.aname)
            if self.dotu:
                self.encF("I", fcall.uidnum)
        elif fcall.type == Rattach:
            self.encQ(fcall.qid)
        elif fcall.type == Twalk:
            self.encF("=IIH", fcall.fid, fcall.newfid,
                    len(fcall.wname))
            for x in fcall.wname:
                self.encS(x)
        elif fcall.type == Rwalk:
            self.encF("H", len(fcall.wqid))
            for x in fcall.wqid:
                self.encQ(x)
        elif fcall.type == Topen:
            self.encF("=IB", fcall.fid, fcall.mode)
        elif fcall.type in (Ropen, Rcreate):
            self.encQ(fcall.qid)
            self.encF("I", fcall.iounit)
        elif fcall.type == Tcreate:
            self.encF("I", fcall.fid)
            self.encS(fcall.name)
            self.encF("=IB", fcall.perm, fcall.mode)
            if self.dotu:
                self.encS(fcall.extension)
        elif fcall.type == Tread:
            self.encF("=IQI", fcall.fid, fcall.offset,
                    fcall.count)
        elif fcall.type == Rread:
            self.encD(fcall.data)
        elif fcall.type == Twrite:
            self.encF("=IQI", fcall.fid, fcall.offset,
                    len(fcall.data))
            self.buf.write(fcall.data)
        elif fcall.type == Rwrite:
            self.encF("I", fcall.count)
        elif fcall.type in (Tclunk,  Tremove, Tstat):
            self.encF("I", fcall.fid)
        elif fcall.type in (Rstat, Twstat):
            if fcall.type == Twstat:
                self.encF("I", fcall.fid)
            self.encstat(fcall.stat, 1)

    def decstat(self, stats, enclen=0):
        if enclen:
            # feed 2 bytes of total size
            self.buf.read(2)
        while self.buf.tell() < self.length:
            self.buf.read(2)

            s = Dir(self.dotu)
            (s.type,
                    s.dev,
                    typ, vers, path,
                    s.mode,
                    s.atime,
                    s.mtime,
                    s.length) = self.decF("=HIBIQIIIQ", 39)
            s.qid = Qid(typ, vers, path)
            s.name = self.decS()     # name
            s.uid = self.decS()      # uid
            s.gid = self.decS()      # gid
            s.muid = self.decS()     # muid
            if self.dotu:
                s.extension = self.decS()
                (s.uidnum,
                        s.gidnum,
                        s.muidnum) = self.decF("=III", 12)
            stats.append(s)

    def dec(self, fcall):
        if fcall.type in (Tversion, Rversion):
            fcall.msize = self.dec4()
            fcall.version = self.decS()
        elif fcall.type == Tauth:
            fcall.afid = self.dec4()
            fcall.uname = self.decS()
            fcall.aname = self.decS()
            if self.dotu:
                fcall.uidnum = self.dec4()
        elif fcall.type == Rauth:
            fcall.aqid = self.decQ()
        elif fcall.type == Rerror:
            fcall.ename = self.decS()
            if self.dotu:
                fcall.errno = self.dec4()
        elif fcall.type == Tflush:
            fcall.oldtag = self.dec2()
        elif fcall.type == Tattach:
            fcall.fid = self.dec4()
            fcall.afid = self.dec4()
            fcall.uname = self.decS()
            fcall.aname = self.decS()
            if self.dotu:
                fcall.uidnum = self.dec4()
        elif fcall.type == Rattach:
            fcall.qid = self.decQ()
        elif fcall.type == Twalk:
            fcall.fid = self.dec4()
            fcall.newfid = self.dec4()
            fcall.nwname = self.dec2()
            fcall.wname = [self.decS().decode('utf-8') for n in range(fcall.nwname)]
        elif fcall.type == Rwalk:
            fcall.nwqid = self.dec2()
            fcall.wqid = [self.decQ() for n in range(fcall.nwqid)]
        elif fcall.type == Topen:
            fcall.fid = self.dec4()
            fcall.mode = self.dec1()
        elif fcall.type in (Ropen, Rcreate):
            fcall.qid = self.decQ()
            fcall.iounit = self.dec4()
        elif fcall.type == Tcreate:
            fcall.fid = self.dec4()
            fcall.name = self.decS().decode('utf-8')
            fcall.perm = self.dec4()
            fcall.mode = self.dec1()
            if self.dotu:
                fcall.extension = self.decS().decode('utf-8')
        elif fcall.type == Tread:
            fcall.fid = self.dec4()
            fcall.offset = self.dec8()
            fcall.count = self.dec4()
        elif fcall.type == Rread:
            fcall.data = self.decD()
        elif fcall.type == Twrite:
            fcall.fid = self.dec4()
            fcall.offset = self.dec8()
            fcall.count = self.dec4()
            fcall.data = self.buf.read(fcall.count)
        elif fcall.type == Rwrite:
            fcall.count = self.dec4()
        elif fcall.type in (Tclunk, Tremove, Tstat):
            fcall.fid = self.dec4()
        elif fcall.type in (Rstat, Twstat):
            if fcall.type == Twstat:
                fcall.fid = self.dec4()
            self.decstat(fcall.stat, 1)

        return fcall


def modetostr(mode):
    bits = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"]

    def b(s):
        return bits[(mode >> s) & 7]
    d = "-"
    if mode & DMDIR:
        d = "d"
    elif mode & DMAPPEND:
        d = "a"
    return "%s%s%s%s" % (d, b(6), b(3), b(0))


def open2stat(mode):
    return (mode & 3) |\
            ((mode & OAPPEND) >> 4) |\
            ((mode & OEXCL) >> 5) |\
            ((mode & OTRUNC) << 5)


def open2plan(mode):
    return (mode & 3) |\
            ((mode & os.O_APPEND) << 4) |\
            ((mode & os.O_EXCL) << 5) |\
            ((mode & os.O_TRUNC) >> 5)


def mode2stat(mode):
    return (mode & 0o777) |\
            ((mode & DMDIR ^ DMDIR) >> 16) |\
            ((mode & DMDIR) >> 17) |\
            ((mode & DMSYMLINK) >> 10) |\
            ((mode & DMSYMLINK) >> 12) |\
            ((mode & DMSETUID) >> 8) |\
            ((mode & DMSETGID) >> 8) |\
            ((mode & DMSTICKY) >> 7)


def mode2plan(mode):
    return (mode & 0o777) | \
            ((mode & stat.S_IFDIR) << 17) |\
            ((mode & stat.S_ISUID) << 8) |\
            ((mode & stat.S_ISGID) << 8) |\
            ((mode & stat.S_ISVTX) << 7) |\
            (int(mode == stat.S_IFLNK) << 25)


def hash8(obj):
    return int(abs(hash(obj)))


def otoa(p):
    '''Convert from open() to access()-style args'''
    ret = 0

    np = p & 3
    if np == OREAD:
        ret = AREAD
    elif np == OWRITE:
        ret = AWRITE
    elif np == ORDWR:
        ret = AREAD | AWRITE
    elif np == OEXEC:
        ret = AEXEC

    if(p & OTRUNC):
        ret |= AWRITE

    return ret


def hasperm(f, uid, p):
    '''Verify permissions for access type 'p' to file 'f'. 'p' is of the type
    returned by otoa() above, i.e., should contain the A* flags.

    f should resemble Dir, i.e., should have f.mode, f.uid, f.gid'''
    m = f.mode & 7  # other
    if (p & m) == p:
        return 1

    if f.uid == uid:
        m |= (f.mode >> 6) & 7
        if (p & m) == p:
            return 1
    if f.gid == uid:
        m |= (f.mode >> 3) & 7
        if (p & m) == p:
            return 1
    return 0


class Sock(object):
    """Per-connection state and appropriate read and write methods
    for the Marshaller."""

    def __init__(self, sock, dotu=0, chatty=0):
        self.sock = sock
        self.fids = {}  # fids are per client
        self.reqs = {}  # reqs are per client
        self.uname = None
        self.closing = False
        self.marshal = Marshal9P(dotu=dotu, chatty=chatty)

    def send(self, x):
        self.marshal.send(self, x)

    def recv(self):
        return self.marshal.recv(self)

    def read(self, l):
        if self.closing:
            return ""
        x = self.sock.recv(l)
        while len(x) < l:
            b = self.sock.recv(l - len(x))
            if not b:
                raise EofError("client eof")
            x += b
        return x

    def write(self, buf):
        if self.closing:
            return len(buf)
        if self.sock.send(buf) != len(buf):
            raise Error("short write")

    def fileno(self):
        return self.sock.fileno()

    def delfid(self, fid):
        if fid in self.fids:
            self.fids[fid].ref = self.fids[fid].ref - 1
            if self.fids[fid].ref == 0:
                del self.fids[fid]

    def getfid(self, fid):
        if fid in self.fids:
            return self.fids[fid]
        return None

    def close(self):
        self.sock.close()


class Fcall(object):
    '''# possible values, from p9p's fcall.h
    msize       # Tversion, Rversion
    version     # Tversion, Rversion
    oldtag      # Tflush
    ename       # Rerror
    qid         # Rattach, Ropen, Rcreate
    iounit      # Ropen, Rcreate
    aqid        # Rauth
    afid        # Tauth, Tattach
    uname       # Tauth, Tattach
    aname       # Tauth, Tattach
    perm        # Tcreate
    name        # Tcreate
    mode        # Tcreate, Topen
    newfid      # Twalk
    nwname      # Twalk
    wname       # Twalk, array
    nwqid       # Rwalk
    wqid        # Rwalk, array
    offset      # Tread, Twrite
    count       # Tread, Twrite, Rread
    data        # Twrite, Rread
    nstat       # Twstat, Rstat
    stat        # Twstat, Rstat

    # dotu extensions:
    errno       # Rerror
    extension   # Tcreate
    '''

    def __init__(self, ftype, tag=1, fid=None):
        self.type = ftype
        self.fid = fid
        self.tag = tag
        self.stat = []
        self.iounit = 8192
        self.ename = None
        self.wqid = None

    def tostr(self):
        attr = [x for x in dir(self) if not x.startswith('_') and
                not x.startswith('tostr')]

        ret = ' '.join("%s=%s" % (x, getattr(self, x)) for x in attr)
        ret = cmdName[self.type] + " " + ret

        return repr(ret)


class Qid(object):

    def __init__(self, qtype=None, vers=None, path=None):
        self.type = qtype
        self.vers = vers
        self.path = path

    def __str__(self):
        return '(%x,%x,%x)' % (self.type, self.vers, self.path)

    __repr__ = __str__


class Fid(object):

    def __init__(self, pool, fid, path='', auth=0):
        if fid in pool:
            raise EdupfidError(Edupfid)
        self.fid = fid
        self.ref = 1
        self.omode = -1
        self.auth = auth
        self.uid = None
        self.qid = None
        self.path = path

        pool[fid] = self


class Dir(object):
    # type:         server type
    # dev           server subtype
    #
    # file data:
    # qid           unique id from server
    # mode          permissions
    # atime         last read time
    # mtime         last write time
    # length        file length
    # name
    # uid           owner name
    # gid           group name
    # muid          last modifier name
    #
    # 9P2000.u extensions:
    # uidnum        numeric uid
    # gidnum        numeric gid
    # muidnum       numeric muid
    # *ext          extended info

    def __init__(self, dotu=0, *args, **kwargs):
        self.dotu = dotu
        self.statsz = 0
        # the dotu arguments will be added separately. this is not
        # straightforward but is cleaner.
        if len(args):
            (self.type,
                self.dev,
                self.qid,
                self.mode,
                self.atime,
                self.mtime,
                self.length,
                self.name,
                self.uid,
                self.gid,
                self.muid) = args[:11]

            if dotu:
                (self.extension,
                    self.uidnum,
                    self.gidnum,
                    self.muidnum) = args[11:15]

        if len(kwargs.keys()):
            for i in kwargs.keys():
                setattr(self, i, kwargs[i])

        if not dotu:
            (self.extension,
                self.uidnum,
                self.gidnum,
                self.muidnum) = "", UIDUNDEF, UIDUNDEF, UIDUNDEF

    def tolstr(self, dirname=''):
        if dirname != '':
            dirname = dirname + '/'
        if self.dotu:
            return "%s %d %d %-8d\t\t%s%s" % (
                    modetostr(self.mode), self.uidnum, self.gidnum,
                    self.length, dirname, self.name)
        else:
            return "%s %s %s %-8d\t\t%s%s" % (
                    modetostr(self.mode), self.uid, self.gid,
                    self.length, dirname, self.name)

    def todata(self, marsh):
        marsh.setBuffer()
        marsh.encstat((self, ), 0)
        return marsh.buf.getvalue()


class Req(object):
    def __init__(self, tag, fd=None, ifcall=None, ofcall=None,
            dir=None, oldreq=None, fid=None, afid=None, newfid=None):
        self.tag = tag
        self.fd = fd
        self.ifcall = ifcall
        self.ofcall = ofcall
        self.dir = dir
        self.oldreq = oldreq
        self.fid = fid
        self.afid = afid
        self.newfid = newfid


class Server(object):
    """
    A server interface to the protocol.
    Subclass this to provide service
    """
    chatty = False
    readpool = []
    writepool = []
    activesocks = {}

    def __init__(self, listen, authmode=None, fs=None, user=None,
            dom=None, key=None, chatty=False, dotu=False, msize=8192):
        self.msize = msize

        if authmode is None:
            self.authfs = None
        elif authmode == 'pki':
            import pki
            self.authfs = pki.AuthFs(key)
        else:
            raise ServerError("unsupported auth mode")

        self.fs = fs
        self.authmode = authmode
        self.dotu = dotu

        self.readpool = []
        self.writepool = []
        self.deferread = {}
        self.deferwrite = {}
        self.user = user
        self.dom = dom
        self.host = listen[0]
        self.port = listen[1]
        self.chatty = chatty

        if self.host[0] == '/':
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                os.unlink(self.host)
            except OSError:
                pass
            self.sock.bind(self.host)
            os.chmod(self.host, self.port)
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.bind((self.host, self.port),)
        self.sock.listen(5)
        self.readpool.append(self.sock)
        if self.chatty:
            print("listening to %s:%d" % (self.host, self.port))

    def mount(self, fs):
        # XXX: for now only allow one mount
        # in the future accept fs/root and
        # handle different filesystems at walk time
        self.fs = fs

    def shutdown(self, sock):
        """Close down a connection."""
        if sock not in self.activesocks:
            return
        s = self.activesocks[sock]
        assert not s.closing  # we looped!
        s.closing = True

        if sock in self.readpool:
            self.readpool.remove(sock)
        if sock in self.writepool:
            self.writepool.remove(sock)

        # find first tag not in use
        tags = [r.ifcall.tag for r in s.reqs]
        tag = [n for n in range(1, 65535) if n not in tags][0]

        # flush all outstanding requests
        for r in s.reqs:
            req = Req(tag)
            req.ifcall = Fcall(Tflush, tag=tag, oldtag=r.ifcall.tag)
            req.ofcall = Fcall(Rflush, tag=tag)
            req.fd = s.fileno()
            req.sock = s
            self.tflush(req)

        # clunk all open fids
        fids = list(s.fids.keys())
        for fid in fids:
            req = Req(tag)
            req.ifcall = Fcall(Tclunk, tag=tag, fid=fid)
            req.ofcall = Fcall(Rclunk, tag=tag)
            req.fd = s.fileno()
            req.sock = s
            self.tclunk(req)

        # flush should have taken care of this
        assert sock not in self.deferwrite and sock not in self.deferread

        sock.close()
        del self.activesocks[sock]

    def serve(self):
        while len(self.readpool) > 0 or len(self.writepool) > 0:
            inr, outr, excr = select.select(self.readpool, self.writepool, [])
            for s in outr:
                if s in self.deferwrite:
                    # this is a fs-delayed req that's just become ready,
                    req = self.deferwrite[s]
                    self.unregwritefd(s)
                    name = cmdName[req.ifcall.type][1:]
                    try:
                        func = getattr(self.fs, name)
                        func(self, req)
                    except:
                        print("error in delayed write response: %s")
                        traceback.print_exc()
                        self.respond(req, "error in delayed response")
                    continue
            for s in inr:
                if s == self.sock:
                    cl, addr = s.accept()
                    self.readpool.append(cl)
                    self.activesocks[cl] = Sock(cl, self.dotu, self.chatty)
                    if self.chatty:
                        print("accepted connection from: %s" % str(addr))
                else:
                    if s in self.deferread:
                        # this is a fs-delayed req that's just become ready,
                        req = self.deferread[s]
                        self.unregreadfd(s)
                        name = cmdName[req.ifcall.type][1:]
                        try:
                            func = getattr(self.fs, name)
                            func(self, req)
                        except:
                            print("error in delayed read response: %s")
                            traceback.print_exc()
                            self.respond(req, "error in delayed response")
                        continue
                    try:
                        self.fromnet(self.activesocks[s])
                    except socket.error as e:
                        if self.chatty:
                            print("socket error: %s" % (e.args[1]))
                            traceback.print_exc()
                        self.shutdown(s)
                    except EofError as e:
                        if self.chatty:
                            print("socket closed: %s" % (e.args[0]))
                        self.readpool.remove(s)
                        self.shutdown(s)
                    except Exception as e:
                        print("error in fromnet (protocol botch?)")
                        traceback.print_exc()
                        print("dropping connection...")
                        self.shutdown(s)

        if self.chatty:
            print("main socket closed")

        return

    def respond(self, req, error=None, errno=None):
        name = 'r' + cmdName[req.ifcall.type][1:]
        if hasattr(self, name):
            func = getattr(self, name)
            try:
                func(req, error)
            except Exception as e:
                print("error in respond: ")
                traceback.print_exc()
                return -1
        else:
            raise ServerError("can not handle message type " +
                    cmdName[req.ifcall.type])

        req.ofcall.tag = req.ifcall.tag
        if error:
            req.ofcall.type = Rerror
            req.ofcall.ename = bytes3(error)
            if not errno:
                errno = ERRUNDEF
            req.ofcall.errno = errno
        s = req.sock
        try:
            s.send(req.ofcall)
        except socket.error as e:
            if self.chatty:
                print("socket error: %s" % (e.args[1]))
                traceback.print_exc()
            self.shutdown(s)
        except EofError as e:
            if self.chatty:
                print("socket closed: %s" % (e.args[0]))
            self.shutdown(s)
        except Exception as e:
            if self.chatty:
                print("socket error: %s" % (str(e.args)))
                traceback.print_exc()
            self.shutdown(s)

        # XXX: unsure whether we need proper flushing semantics from rsc's p9p
        # thing is, we're not threaded.

    def fromnet(self, fd):
        fcall = fd.recv()
        req = Req(fcall.tag)
        req.ifcall = fcall
        req.ofcall = Fcall(fcall.type + 1, fcall.tag)
        req.fd = fd.fileno()
        req.sock = fd

        if req.ifcall.type not in cmdName:
            self.respond(req, "invalid message")

        name = "t" + cmdName[req.ifcall.type][1:]
        if hasattr(self, name):
            func = getattr(self, name)
            try:
                func(req)
            except Error as e:
                if self.chatty:
                    traceback.print_exc()
                self.respond(req, 'server error:' + str(e.args[0][1]),
                        e.args[0][0])
            except Exception as e:
                if self.chatty:
                    traceback.print_exc()
                self.respond(req, 'unhandled internal exception: ' +
                        str(e.args[0]))
        else:
            self.respond(req, "unhandled message: %s" % (
                cmdName[req.ifcall.type]))
        return

    def regreadfd(self, fd, req):
        '''Register a file descriptor in the read pool. When a fileserver
        wants to delay responding to a message they can register an fd and
        have it polled for reading. When it's ready, the corresponding 'req'
        will be called'''
        self.deferread[fd] = req
        self.readpool.append(fd)

    def regwritefd(self, fd, req):
        '''Register a file descriptor in the write pool.'''
        self.deferwrite[fd] = req
        self.writepool.append(fd)

    def unregreadfd(self, fd):
        '''Delete a fd registered with regreadfd().'''
        del self.deferread[fd]
        self.readpool.remove(fd)

    def unregwritefd(self, fd):
        '''Delete a fd registered with regwritefd().'''
        del self.deferwrite[fd]
        self.writepool.remove(fd)

    def tversion(self, req):
        if req.ifcall.version[0:2] != b'9P':
            req.ofcall.version = "unknown"
            self.respond(req, None)
            return

        if req.ifcall.version == versionu:
            # dotu is passed to server init to indicate whether dotu
            # will be supported
            #
            # if the server init code was told not to implement dotu
            # then even if the remote wants dotu we must fall back to 9P2000
            if self.dotu:
                req.ofcall.version = versionu
            else:
                req.ofcall.version = version
        else:
            # if somebody requested a later version of the protocol
            # (9Pxxxx.y, for xxxx>2000) then fall back to what we know
            # best: 9P2000;
            #
            # if somebody requested 9Pxxxx for xxxx<2000 then we have no
            # clue what to say and we just keep repeating the same.
            req.ofcall.version = version
            req.sock.marshal.dotu = 0

        req.ofcall.msize = min(req.ifcall.msize, self.msize)
        self.respond(req, None)

    def rversion(self, req, error):
        # self.msize = req.ofcall.msize
        pass

    def tauth(self, req):
        if self.authfs is None:
            self.respond(req, "%s: authentication not required" %
                    (sys.argv[0]))
            return

        try:
            req.afid = Fid(req.sock.fids, req.ifcall.afid, auth=1)
        except EdupfidError:
            self.respond(req, Edupfid)
            return
        req.afid.uname = req.ifcall.uname
        self.authfs.estab(req.afid)
        req.afid.qid = Qid(QTAUTH, 0, hash8('#a'))
        req.ofcall.aqid = req.afid.qid
        self.respond(req, None)

    def rauth(self, req, error):
        if error and req.afid:
            req.sock.delfid(req.afid.fid)

    def tattach(self, req):
        try:
            req.fid = Fid(req.sock.fids, req.ifcall.fid)
        except EdupfidError:
            self.respond(req, Edupfid)
            return

        req.afid = None
        if req.ifcall.afid != NOFID:
            req.afid = req.sock.fids[req.ifcall.afid]
            if not req.afid:
                self.respond(req, Eunknownfid)
                return
            if req.afid.suid != req.ifcall.uname:
                self.respond(req, "not authenticated as %r" % req.ifcall.uname)
                return
            elif self.chatty:
                print("authenticated as %r" % req.ifcall.uname)
        elif self.authmode is not None:
            self.respond(req, 'authentication not complete')

        req.fid.uid = req.ifcall.uname
        req.sock.uname = req.ifcall.uname  # now we know who we are
        if hasattr(self.fs, 'attach'):
            self.fs.attach()
        else:
            req.ofcall.qid = self.fs.root.qid
            req.fid.qid = self.fs.root.qid
            self.respond(req, None)
        return

    def rattach(self, req, error):
        if error and req.fid:
            req.sock.delfid(req.fid.fid)

    def tflush(self, req):
        if hasattr(self.fs, 'flush'):
            self.fs.flush(self, req)
        else:
            req.sock.reqs = []
            self.respond(req, None)

    def rflush(self, req, error):
        if req.oldreq:
            if req.oldreq.responded == 0:
                req.oldreq.nflush = req.oldreq.nflush + 1
                if not hasattr(req.oldreq, 'flush'):
                    req.oldreq.nflush = 0
                    req.oldreq.flush = []
                req.oldreq.nflush = req.oldreq.nflush + 1
                req.oldreq.flush.append(req)
        req.oldreq = None
        return 0

    def twalk(self, req):
        req.ofcall.wqid = []

        req.fid = req.sock.getfid(req.ifcall.fid)
        if not req.fid:
            self.respond(req, Eunknownfid)
            return
        if req.fid.omode != -1:
            self.respond(req, "cannot clone open fid")
            return
        if len(req.ifcall.wname) and not (req.fid.qid.type & QTDIR):
            self.respond(req, Ewalknotdir)
            return
        if req.ifcall.fid != req.ifcall.newfid:
            try:
                req.newfid = Fid(req.sock.fids, req.ifcall.newfid)
            except EdupfidError:
                self.respond(req, Edupfid)
                return
            req.newfid.uid = req.fid.uid
        else:
            req.fid.ref = req.fid.ref + 1
            req.newfid = req.fid

        if len(req.ifcall.wname) == 0:
            req.ofcall.nwqid = 0
            self.respond(req, None)
        elif hasattr(self.fs, 'walk'):
            self.fs.walk(self, req)
        else:
            self.respond(req, "no walk function")

    def rwalk(self, req, error):
        if error or (len(req.ofcall.wqid) < len(req.ifcall.wname) and
                len(req.ifcall.wname) > 0):
            if req.ifcall.fid != req.ifcall.newfid and req.newfid:
                req.sock.delfid(req.ifcall.newfid)
            if len(req.ofcall.wqid) == 0:
                if not error and len(req.ifcall.wname) != 0:
                    req.error = Enotfound
            else:
                req.error = None
        else:
            if len(req.ofcall.wqid) == 0:
                req.newfid.qid = req.fid.qid
            else:
                req.newfid.qid = req.ofcall.wqid[-1]

    def topen(self, req):
        req.fid = req.sock.getfid(req.ifcall.fid)
        if not req.fid:
            self.respond(req, Eunknownfid)
            return
        if req.fid.omode != -1:
            self.respond(req, Ebotch)
            return
        if req.fid.qid.type & QTDIR:
            if (req.ifcall.mode & (~ORCLOSE)) != OREAD:
                self.respond(req, Eisdir)
                return
            # repeating the same bug as p9p?
            if otoa(req.ifcall.mode) != AREAD:
                self.respond(req, Eisdir)
                return

        req.ofcall.qid = req.fid.qid
        req.ofcall.iounit = self.msize - IOHDRSZ
        req.ifcall.acc = [AREAD, AWRITE,
                AREAD | AWRITE, AEXEC][req.ifcall.mode & 3]
        if req.ifcall.mode & OTRUNC:
            req.ifcall.acc |= AWRITE

        if (req.fid.qid.type & QTDIR) and (req.ifcall.acc != AREAD):
            self.respond(req, Eperm)
        if hasattr(self.fs, 'open'):
            self.fs.open(self, req)
        else:
            self.respond(req, None)

    def ropen(self, req, error):
        if error:
            return
        req.fid.omode = req.ifcall.mode
        req.fid.qid = req.ofcall.qid
        if req.ofcall.qid.type & QTDIR:
            req.fid.diroffset = 0

    def tcreate(self, req):
        req.fid = req.sock.getfid(req.ifcall.fid)
        if not req.fid:
            self.respond(req, Eunknownfid)
        elif req.fid.omode != -1:
            self.respond(req, Ebotch)
        elif not (req.fid.qid.type & QTDIR):
            self.respond(req, Ecreatenondir)
        elif hasattr(self.fs, 'create'):
            self.fs.create(self, req)
        else:
            self.respond(req, Enocreate)

    def rcreate(self, req, error):
        if error:
            return
        req.fid.omode = req.ifcall.mode
        req.fid.qid = req.ofcall.qid
        req.ofcall.iounit = self.msize - IOHDRSZ

    def bufread(self, req, buf):
        req.ofcall.data = buf[req.ifcall.offset: req.ifcall.offset +
                req.ifcall.count]
        return self.respond(req, None)

    def tread(self, req):
        req.fid = req.sock.getfid(req.ifcall.fid)
        if not req.fid:
            return self.respond(req, Eunknownfid)
        if req.ifcall.count < 0:
            return self.respond(req, Ebotch)
        if req.ifcall.offset < 0 or ((req.fid.qid.type & QTDIR) and
                (req.ifcall.offset != 0) and
                (req.ifcall.offset != req.fid.diroffset)):
            return self.respond(req, Ebadoffset)
        if req.fid.qid.type & QTAUTH and self.authfs:
            self.authfs.read(self, req)
            return
        # auth Tread goes w/o omode, there was no open()
        if req.fid.omode == -1:
            return self.respond(req, Eopen)

        if req.ifcall.count > self.msize - IOHDRSZ:
            req.ifcall.count = self.msize - IOHDRSZ
        o = req.fid.omode & 3
        if o != OREAD and o != ORDWR and o != OEXEC:
            return self.respond(req, Ebotch)
        if hasattr(self.fs, 'read'):
            self.fs.read(self, req)
        else:
            self.respond(req, 'no server read function')

    def rread(self, req, error):
        if error:
            return

        if req.fid.qid.type & QTDIR:
            data = b""
            for x in req.ofcall.stat:
                ndata = x.todata(req.sock.marshal)
                if (len(data) - req.ifcall.offset) + \
                        len(ndata) < req.ifcall.count:
                    data = data + ndata
                else:
                    break
            req.ofcall.data = data[req.ifcall.offset:]
            req.fid.diroffset = req.ifcall.offset + len(req.ofcall.data)

    def twrite(self, req):
        req.fid = req.sock.getfid(req.ifcall.fid)
        if not req.fid:
            return self.respond(req, Eunknownfid)
        if req.ifcall.count < 0 or req.ifcall.offset < 0:
            return self.respond(req, Ebotch)
        if req.fid.qid.type & QTAUTH and self.authfs:
            self.authfs.write(self, req)
            return
        # auth Tread goes w/o omode, there was no open()
        if req.fid.omode == -1:
            return self.respond(req, Eopen)

        if req.ifcall.count > self.msize - IOHDRSZ:
            req.ifcall.count = self.msize - IOHDRSZ
        o = req.fid.omode & 3
        if o != OWRITE and o != ORDWR:
            return self.respond(req,
                    "write on fid with open mode 0x%ux" % req.fid.omode)
        if hasattr(self.fs, 'write'):
            self.fs.write(self, req)
        else:
            self.respond(req, 'no server write function')

    def rwrite(self, req, error):
        return

    def tclunk(self, req):
        req.fid = req.sock.getfid(req.ifcall.fid)
        if not req.fid:
            return self.respond(req, Eunknownfid)
        if hasattr(self.fs, 'clunk') and not (req.fid.qid.type & QTAUTH):
            self.fs.clunk(self, req)
        else:
            self.respond(req, None)
        req.sock.delfid(req.ifcall.fid)

    def rclunk(self, req, error):
        return

    def tremove(self, req):
        req.fid = req.sock.getfid(req.ifcall.fid)
        if not req.fid:
            return self.respond(req, Eunknownfid)
        if hasattr(self.fs, 'remove'):
            self.fs.remove(self, req)
        else:
            self.respond(req, Enoremove)

    def rremove(self, req, error):
        req.sock.delfid(req.ifcall.fid)
        return

    def tstat(self, req):
        req.fid = req.sock.getfid(req.ifcall.fid)
        req.ofcall.stat = []
        if not req.fid:
            return self.respond(req, Eunknownfid)
        if hasattr(self.fs, 'stat'):
            self.fs.stat(self, req)
        else:
            self.respond(req, Enostat)

    def rstat(self, req, error):
        if error:
            return

    def twstat(self, req):
        req.fid = req.sock.getfid(req.ifcall.fid)
        if not req.fid:
            return self.respond(req, Eunknownfid)
        if hasattr(self.fs, 'wstat'):
            self.fs.wstat(self, req)
        else:
            self.respond(req, Enowstat)

    def rwstat(self, req, error):
        return


class Credentials(object):
    def __init__(self, user, authmode=None, passwd=None,
            keyfile=None, key=None):
        self.user = bytes3(user) if isinstance(user, str) else user
        self.passwd = bytes3(passwd) if isinstance(passwd, str) else passwd
        self.key = key
        self.authmode = authmode
        if self.authmode == "pki":
            import pki
            self.key = pki.getprivkey(user, keyfile, passwd)


class Client(object):
    """
    A client interface to the protocol.
    """
    AFID = 10
    ROOT = 11
    CWD = 12
    F = 13

    path = ''  # for 'getwd' equivalent

    def __init__(self, fd, credentials, authsrv=None, chatty=0, dotu=0,
            msize=8192):
        self.credentials = credentials
        self.dotu = dotu
        self.msize = msize
        self.fd = Sock(fd, dotu, chatty)
        self.login(authsrv, credentials)

    def _rpc(self, fcall):
        if fcall.type == Tversion:
            fcall.tag = NOTAG
        self.fd.send(fcall)
        try:
            ifcall = self.fd.recv()
        except (KeyboardInterrupt, Exception):
            # try to flush the operation, then rethrow exception
            if fcall.type != Tflush:
                try:
                    self._flush(fcall.tag, fcall.tag + 1)
                except Exception:
                    pass
            raise
        if ifcall.tag != fcall.tag:
            raise RpcError("invalid tag received")
        if ifcall.type == Rerror:
            raise RpcError(ifcall.ename)
        if ifcall.type != fcall.type + 1:
            raise ClientError("incorrect reply from server: %r" %
                    [fcall.type, fcall.tag])
        return ifcall

    # protocol calls; part of 9p
    # should be private functions, really
    def _version(self, msize, version):
        fcall = Fcall(Tversion)
        self.msize = msize
        fcall.msize = msize
        fcall.version = version
        return self._rpc(fcall)

    def _auth(self, afid, uname, aname):
        fcall = Fcall(Tauth)
        fcall.afid = afid
        fcall.uname = uname
        fcall.aname = aname
        fcall.uidnum = 0
        return self._rpc(fcall)

    def _attach(self, fid, afid, uname, aname):
        fcall = Fcall(Tattach)
        fcall.fid = fid
        fcall.afid = afid
        fcall.uname = uname
        fcall.aname = aname
        fcall.uidnum = 0
        return self._rpc(fcall)

    def _walk(self, fid, newfid, wnames):
        fcall = Fcall(Twalk)
        fcall.fid = fid
        fcall.newfid = newfid
        fcall.wname = [bytes3(x) for x in wnames]
        return self._rpc(fcall)

    def _open(self, fid, mode):
        fcall = Fcall(Topen)
        fcall.fid = fid
        fcall.mode = mode
        return self._rpc(fcall)

    def _create(self, fid, name, perm, mode, extension=b""):
        fcall = Fcall(Tcreate)
        fcall.fid = fid
        fcall.name = name
        fcall.perm = perm
        fcall.mode = mode
        fcall.extension = extension
        return self._rpc(fcall)

    def _read(self, fid, off, count):
        fcall = Fcall(Tread)
        fcall.fid = fid
        fcall.offset = off
        if count > self.msize - IOHDRSZ:
            count = self.msize - IOHDRSZ
        fcall.count = count
        return self._rpc(fcall)

    def _write(self, fid, off, data):
        fcall = Fcall(Twrite)
        fcall.fid = fid
        fcall.offset = off
        fcall.data = data
        return self._rpc(fcall)

    def _clunk(self, fid):
        fcall = Fcall(Tclunk)
        fcall.fid = fid
        return self._rpc(fcall)

    def _remove(self, fid):
        fcall = Fcall(Tremove)
        fcall.fid = fid
        return self._rpc(fcall)

    def _stat(self, fid):
        fcall = Fcall(Tstat)
        fcall.fid = fid
        return self._rpc(fcall)

    def _wstat(self, fid, stats):
        fcall = Fcall(Twstat)
        fcall.fid = fid
        fcall.stat = stats
        return self._rpc(fcall)

    def _flush(self, tag, oldtag):
        fcall = Fcall(Tflush, tag=tag)
        fcall.oldtag = tag
        return self._rpc(fcall)

    def _fullclose(self):
        self._clunk(self.ROOT)
        self._clunk(self.CWD)
        self.fd.close()

    def login(self, authsrv, credentials):
        if self.dotu:
            ver = versionu
        else:
            ver = version
        fcall = self._version(self.msize, ver)
        self.msize = fcall.msize
        if fcall.version != ver:
            raise VersionError("version mismatch: %r" % fcall.version)

        fcall.afid = self.AFID
        try:
            rfcall = self._auth(fcall.afid, credentials.user, b'')
        except RpcError as e:
            fcall.afid = NOFID

        if fcall.afid != NOFID:
            fcall.aqid = rfcall.aqid

            if credentials.authmode is None:
                raise ClientError('no authentication method')
            elif credentials.authmode == 'pki':
                import pki
                pki.clientAuth(self, fcall, credentials)
            else:
                raise ClientError('unknown authentication method: %s' %
                        credentials.authmode)

        self._attach(self.ROOT, fcall.afid, credentials.user, b'')
        if fcall.afid != NOFID:
            self._clunk(fcall.afid)
        self._walk(self.ROOT, self.CWD, [])
        self.path = '/'

    # user accessible calls, the actual implementation of a client
    def close(self):
        self._clunk(self.F)

    def walk(self, pstr=''):
        root = self.CWD
        if pstr == '':
            path = []
        elif pstr.find('/') == -1:
            path = [pstr]
        else:
            path = pstr.split('/')
            if path[0] == '':
                root = self.ROOT
                path = path[1:]
            path = list(filter(None, path))
        try:
            fcall = self._walk(root, self.F, path)
        except RpcError:
            raise

        if len(fcall.wqid) < len(path):
            raise RpcError('incomplete walk (%d out of %d)' %
                    (len(fcall.wqid), len(path)))
        return fcall.wqid

    def open(self, pstr='', mode=0):
        if self.walk(pstr) is None:
            return
        self.pos = 0
        try:
            fcall = self._open(self.F, mode)
        except RpcError:
            self.close()
            raise
        return fcall

    def create(self, pstr, perm=0o644, mode=1):
        p = pstr.split('/')
        pstr2, name = '/'.join(p[:-1]), p[-1]
        if self.walk(pstr2) is None:
            return
        self.pos = 0
        try:
            return self._create(self.F, name, perm, mode)
        except RpcError:
            self.close()
            raise

    def rm(self, pstr):
        self.open(pstr)
        try:
            self._remove(self.F)
        except RpcError:
            raise

    def read(self, l):
        try:
            fcall = self._read(self.F, self.pos, l)
            buf = fcall.data
        except RpcError:
            self.close()
            raise

        self.pos += len(buf)
        return buf

    def write(self, buf):
        try:
            l = self._write(self.F, self.pos, buf).count
            self.pos += l
            return l
        except RpcError:
            self.close()
            raise

    def stat(self, pstr):
        if self.walk(pstr) is None:
            return
        try:
            fc = self._stat(self.F)
        finally:
            self.close()
        return fc.stat

    def lsdir(self):
        ret = []
        while 1:
            buf = self.read(self.msize)
            if len(buf) == 0:
                break
            p9 = Marshal9P()
            p9.setBuffer(buf)
            p9.buf.seek(0)
            fcall = Fcall(Rstat)
            try:
                p9.decstat(fcall.stat, 0)
            except:
                self.close()
                print('unexpected decstat error:')
                traceback.print_exc()
                raise
            ret += fcall.stat
        return ret

    def ls(self, long=0, args=[]):
        ret = []

        if len(args) == 0:
            if self.open() is None:
                return
            if long:
                ret = [z.tolstr() for z in self.lsdir()]
            else:
                ret = [z.name for z in self.lsdir()]
            self.close()
        else:
            for x in args:
                stat = self.stat(x)
                if not stat:
                    return  # stat already printed a message
                if len(stat) == 1:
                    if stat[0].mode & DMDIR:
                        self.open(x)
                        lsd = self.lsdir()
                        if long:
                            ret += [z.tolstr() for z in lsd]
                        else:
                            ret += [x + '/' + z.name for z in lsd]
                        self.close()
                    else:
                        if long:
                            # we already have full path+name, but tolstr()
                            # wants to append the name to the end anyway, so
                            # strip the last basename out to form identical
                            # path+name
                            ret.append(stat[0].tolstr(
                                x[0:-len(stat[0].name) - 1]))
                        else:
                            ret.append(x)
                else:
                    print('%s: returned multiple stats (internal error)' % x)
        return ret

    def cd(self, pstr):
        q = self.walk(pstr)
        if q is None:
            return 0
        if q and not (q[-1].type & QTDIR):
            print("%s: not a directory" % pstr)
            self.close()
            return 0
        self.F, self.CWD = self.CWD, self.F
        self.close()
        return 1
