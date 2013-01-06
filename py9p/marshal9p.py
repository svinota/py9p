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

import io
import py9p
import threading
import struct


class Buffer(io.BytesIO):

    @property
    def length(self):
        p = self.tell()
        self.seek(0, 2)
        l = self.tell()
        self.seek(p)
        return l

    def enc1(self, x):
        """Encode 1-byte unsigned"""
        self.write(struct.pack('B', x))

    def dec1(self):
        """Decode 1-byte unsigned"""
        return struct.unpack('b', self.read(1))[0]

    def enc2(self, x):
        """Encode 2-byte unsigned"""
        self.write(struct.pack('H', x))

    def dec2(self):
        """Decode 2-byte unsigned"""
        return struct.unpack('H', self.read(2))[0]

    def enc4(self, x):
        """Encode 4-byte unsigned"""
        self.write(struct.pack('I', x))

    def dec4(self):
        """Decode 4-byte unsigned"""
        return struct.unpack('I', self.read(4))[0]

    def enc8(self, x):
        """Encode 8-byte unsigned"""
        self.write(struct.pack('Q', x))

    def dec8(self):
        """Decode 8-byte unsigned"""
        return struct.unpack('Q', self.read(8))[0]

    def encS(self, x):
        """Encode data string with 2-byte length"""
        self.write(struct.pack("H", len(x)))
        self.write(x)

    def decS(self):
        """Decode data string with 2-byte length"""
        return self.read(self.dec2())

    def encD(self, d):
        """Encode data string with 4-byte length"""
        self.write(struct.pack("I", len(d)))
        self.write(d)

    def decD(self):
        """Decode data string with 4-byte length"""
        return self.read(self.dec4())

    def encF(self, *argv):
        """Encode data directly by struct.pack"""
        self.write(struct.pack(*argv))

    def decF(self, fmt, length):
        """Decode data by struct.unpack"""
        return struct.unpack(fmt, self.read(length))

    def encQ(self, q):
        """Encode Qid structure"""
        self.encF("=BIQ", q.type, q.vers, q.path)

    def decQ(self):
        """Decode Qid structure"""
        return py9p.Qid(self.dec1(), self.dec4(), self.dec8())


class Marshal9P(object):
    chatty = False

    def __init__(self, dotu=0, chatty=False):
        self.chatty = chatty
        self.dotu = dotu
        self._lock = threading.Lock()
        self.buf = Buffer()

    def _checkType(self, t):
        if t not in py9p.cmdName:
            raise py9p.Error("Invalid message type %d" % t)

    def _checkSize(self, v, mask):
        if v != v & mask:
            raise py9p.Error("Invalid value %d" % v)

    def _checkLen(self, x, l):
        if len(x) != l:
            raise py9p.Error("Wrong length %d, expected %d: %r" % (
                len(x), l, x))

    def setBuffer(self, init=""):
        self.buf.seek(0)
        self.buf.truncate()
        self.buf.write(init)

    def send(self, fd, fcall):
        "Format and send a message"
        with self._lock:
            self.setBuffer("0000")
            self._checkType(fcall.type)
            if self.chatty:
                print "-%d->" % fd.fileno(), py9p.cmdName[fcall.type], \
                    fcall.tag, fcall.tostr()
            self.enc(fcall)
            self.buf.seek(0)
            self.buf.enc4(self.buf.length)
            fd.write(self.buf.getvalue())

    def recv(self, fd):
        "Read and decode a message"
        with self._lock:
            size = struct.unpack("I", fd.read(4))[0]
            if size > 0xffffffff or size < 7:
                raise py9p.Error("Bad message size: %d" % size)
            self.setBuffer(fd.read(size - 4))
            self.buf.seek(0)
            type, tag = self.buf.decF("=BH", 3)
            self._checkType(type)
            fcall = py9p.Fcall(type, tag)
            self.dec(fcall)
            # self._checkResid() -- FIXME
            if self.chatty:
                print "<-%d- %s %s %s" % (fd.fileno(), py9p.cmdName[type],
                        tag, fcall.tostr())
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
            self.buf.enc2(statsz + 2)

        for x in stats:
            self.buf.encF("=HHIBIQIIIQ",
                    x.statsz, x.type, x.dev, x.qid.type, x.qid.vers,
                    x.qid.path, x.mode, x.atime, x.mtime, x.length)
            self.buf.encS(x.name)
            self.buf.encS(x.uid)
            self.buf.encS(x.gid)
            self.buf.encS(x.muid)
            if self.dotu:
                self.buf.encS(x.extension)
                self.buf.encF("=III",
                        x.uidnum, x.gidnum, x.muidnum)

    def enc(self, fcall):
        self.buf.encF("=BH", fcall.type, fcall.tag)
        if fcall.type in (py9p.Tversion, py9p.Rversion):
            self.buf.encF("I", fcall.msize)
            self.buf.encS(fcall.version)
        elif fcall.type == py9p.Tauth:
            self.buf.encF("I", fcall.afid)
            self.buf.encS(fcall.uname)
            self.buf.encS(fcall.aname)
            if self.dotu:
                self.buf.encF("I", fcall.uidnum)
        elif fcall.type == py9p.Rauth:
            self.buf.encQ(fcall.aqid)
        elif fcall.type == py9p.Rerror:
            self.buf.encS(fcall.ename)
            if self.dotu:
                self.buf.encF("I", fcall.errno)
        elif fcall.type == py9p.Tflush:
            self.buf.encF("H", fcall.oldtag)
        elif fcall.type == py9p.Tattach:
            self.buf.encF("=II", fcall.fid, fcall.afid)
            self.buf.encS(fcall.uname)
            self.buf.encS(fcall.aname)
            if self.dotu:
                self.buf.encF("I", fcall.uidnum)
        elif fcall.type == py9p.Rattach:
            self.buf.encQ(fcall.qid)
        elif fcall.type == py9p.Twalk:
            self.buf.encF("=IIH", fcall.fid, fcall.newfid,
                    len(fcall.wname))
            for x in fcall.wname:
                self.buf.encS(x)
        elif fcall.type == py9p.Rwalk:
            self.buf.encF("H", len(fcall.wqid))
            for x in fcall.wqid:
                self.buf.encQ(x)
        elif fcall.type == py9p.Topen:
            self.buf.encF("=IB", fcall.fid, fcall.mode)
        elif fcall.type in (py9p.Ropen, py9p.Rcreate):
            self.buf.encQ(fcall.qid)
            self.buf.encF("I", fcall.iounit)
        elif fcall.type == py9p.Tcreate:
            self.buf.encF("I", fcall.fid)
            self.buf.encS(fcall.name)
            self.buf.encF("=IB", fcall.perm, fcall.mode)
            if self.dotu:
                self.buf.encS(fcall.extension)
        elif fcall.type == py9p.Tread:
            self.buf.encF("=IQI", fcall.fid, fcall.offset,
                    fcall.count)
        elif fcall.type == py9p.Rread:
            self.buf.encD(fcall.data)
        elif fcall.type == py9p.Twrite:
            self.buf.encF("=IQI", fcall.fid, fcall.offset,
                    len(fcall.data))
            self.buf.write(fcall.data)
        elif fcall.type == py9p.Rwrite:
            self.buf.encF("I", fcall.count)
        elif fcall.type in (py9p.Tclunk,  py9p.Tremove, py9p.Tstat):
            self.buf.encF("I", fcall.fid)
        elif fcall.type in (py9p.Rstat, py9p.Twstat):
            if fcall.type == py9p.Twstat:
                self.buf.encF("I", fcall.fid)
            self.encstat(fcall.stat, 1)

    def decstat(self, stats, enclen=0):
        if enclen:
            # feed 2 bytes of total size
            self.buf.read(2)
        while self.buf.tell() < self.buf.length:
            self.buf.read(2)

            stat = py9p.Dir(self.dotu)
            (stat.type,
                    stat.dev,
                    typ, vers, path,
                    stat.mode,
                    stat.atime,
                    stat.mtime,
                    stat.length) = self.buf.decF("=HIBIQIIIQ", 39)
            stat.qid = py9p.Qid(typ, vers, path)
            stat.name = self.buf.decS()     # name
            stat.uid = self.buf.decS()      # uid
            stat.gid = self.buf.decS()      # gid
            stat.muid = self.buf.decS()     # muid
            if self.dotu:
                stat.extension = self.buf.decS()
                (stat.uidnum,
                        stat.gidnum,
                        stat.muidnum) = self.buf.decF("=III", 12)
            stats.append(stat)

    def dec(self, fcall):
        if fcall.type in (py9p.Tversion, py9p.Rversion):
            fcall.msize = self.buf.dec4()
            fcall.version = self.buf.decS()
        elif fcall.type == py9p.Tauth:
            fcall.afid = self.buf.dec4()
            fcall.uname = self.buf.decS()
            fcall.aname = self.buf.decS()
            if self.dotu:
                fcall.uidnum = self.buf.dec4()
        elif fcall.type == py9p.Rauth:
            fcall.aqid = self.buf.decQ()
        elif fcall.type == py9p.Rerror:
            fcall.ename = self.buf.decS()
            if self.dotu:
                fcall.errno = self.buf.dec4()
        elif fcall.type == py9p.Tflush:
            fcall.oldtag = self.buf.dec2()
        elif fcall.type == py9p.Tattach:
            fcall.fid = self.buf.dec4()
            fcall.afid = self.buf.dec4()
            fcall.uname = self.buf.decS()
            fcall.aname = self.buf.decS()
            if self.dotu:
                fcall.uidnum = self.buf.dec4()
        elif fcall.type == py9p.Rattach:
            fcall.qid = self.buf.decQ()
        elif fcall.type == py9p.Twalk:
            fcall.fid = self.buf.dec4()
            fcall.newfid = self.buf.dec4()
            fcall.nwname = self.buf.dec2()
            fcall.wname = [self.buf.decS() for n in xrange(fcall.nwname)]
        elif fcall.type == py9p.Rwalk:
            fcall.nwqid = self.buf.dec2()
            fcall.wqid = [self.buf.decQ() for n in xrange(fcall.nwqid)]
        elif fcall.type == py9p.Topen:
            fcall.fid = self.buf.dec4()
            fcall.mode = self.buf.dec1()
        elif fcall.type in (py9p.Ropen, py9p.Rcreate):
            fcall.qid = self.buf.decQ()
            fcall.iounit = self.buf.dec4()
        elif fcall.type == py9p.Tcreate:
            fcall.fid = self.buf.dec4()
            fcall.name = self.buf.decS()
            fcall.perm = self.buf.dec4()
            fcall.mode = self.buf.dec1()
            if self.dotu:
                fcall.extension = self.buf.decS()
        elif fcall.type == py9p.Tread:
            fcall.fid = self.buf.dec4()
            fcall.offset = self.buf.dec8()
            fcall.count = self.buf.dec4()
        elif fcall.type == py9p.Rread:
            fcall.data = self.buf.decD()
        elif fcall.type == py9p.Twrite:
            fcall.fid = self.buf.dec4()
            fcall.offset = self.buf.dec8()
            fcall.count = self.buf.dec4()
            fcall.data = self.buf.read(fcall.count)
        elif fcall.type == py9p.Rwrite:
            fcall.count = self.buf.dec4()
        elif fcall.type in (py9p.Tclunk, py9p.Tremove, py9p.Tstat):
            fcall.fid = self.buf.dec4()
        elif fcall.type in (py9p.Rstat, py9p.Twstat):
            if fcall.type == py9p.Twstat:
                fcall.fid = self.buf.dec4()
            self.decstat(fcall.stat, 1)

        return fcall
