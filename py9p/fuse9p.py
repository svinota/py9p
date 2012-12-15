#!/usr/bin/python

import socket
import sys
import os
import pwd
import grp
import fuse
import stat
import errno
import time
import threading
import marshal9p
import py9p
import traceback

MIN_TFID = 64
MAX_TFID = 1023
MIN_FID = 1024
MAX_FID = 65535
MAX_RECONNECT_INTERVAL = 1024

rpccodes = {
        "duplicate fid": -errno.EBADFD,
        "unknown fid": -errno.EBADFD,
        "create prohibited": -errno.EPERM,
        "remove prohibited": -errno.EPERM,
        "stat prohibited": -errno.EPERM,
        "wstat prohibited": -errno.EPERM,
        "permission denied": -errno.EPERM}


class Error(py9p.Error):
    pass


class NoFidError(Exception):
    pass


fuse.fuse_python_api = (0, 2)


class fStat(fuse.Stat):
    """
    FUSE stat structure, that will represent PyVFS Inode
    """
    def __init__(self, inode):
        self.st_mode = py9p.mode2stat(inode.mode)
        self.st_ino = 0
        self.st_dev = 0
        if inode.mode & stat.S_IFDIR:
            self.st_nlink = inode.length
        else:
            self.st_nlink = 1
        self.st_uid = inode.uidnum
        self.st_gid = inode.gidnum
        self.st_size = inode.length
        self.st_atime = inode.atime
        self.st_mtime = inode.mtime
        self.st_ctime = inode.mtime


class fakeRoot(fuse.Stat):
    """
    Fake empty root for disconnected state
    """
    def __init__(self):
        self.st_mode = stat.S_IFDIR | 0o755
        self.st_ino = 0
        self.st_dev = 0
        self.st_nlink = 3
        self.st_uid = 0
        self.st_gid = 0
        self.st_size = 3
        self.st_atime = self.st_mtime = self.st_ctime = time.time()


def guard(c):
    """
    The decorator function, specific for ClientFS class

        * acqiures and releases temporary fid
        * deals with py9p RPC errors
        * triggers reconnect() on network errors
    """
    def wrapped(self, *argv, **kwarg):
        ret = -errno.EIO
        tfid = None
        try:
            tfid = self.tfidcache.acquire()
            ret = c(self, tfid.fid, *argv, **kwarg)
        except NoFidError:
            ret = -errno.EMFILE
        except py9p.RpcError as e:
            ret = rpccodes.get(e.message, -errno.EIO)
        except:
            if self.debug:
                traceback.print_exc()
            if self.keep_reconnect:
                self._reconnect()
            else:
                sys.exit(255)
        if tfid is not None:
            self.tfidcache.release(tfid)
        return ret
    return wrapped


class FidCache(dict):
    """
    Fid cache class

    The class provides API to acquire next not used Fid
    for the 9p operations. If there is no free Fid available,
    it raises NoFidError(). After usage, Fid should be freed
    and returned to the cache with release() method.
    """
    def __init__(self, start=MIN_FID, limit=MAX_FID):
        """
         * start -- the Fid interval beginning
         * limit -- the Fid interval end

        All acquired Fids will be from this interval.
        """
        dict.__init__(self)
        self.start = start
        self.limit = limit
        self.fids = list(range(self.start, self.limit + 1))

    def acquire(self):
        """
        Acquire next available Fid
        """
        if len(self.fids) < 1:
            raise NoFidError()
        return Fid(self.fids.pop(0))

    def release(self, f):
        """
        Return Fid to the free Fids queue.
        """
        self.fids.append(f.fid)


class Fid(object):
    """
    Fid class

    It is used also in the stateful I/O, representing
    the open file. All methods, working with open files,
    will receive Fid as the last parameter.

    See: write(), read(), release()
    """
    def __init__(self, fid):
        self.fid = fid


class ClientFS(fuse.Fuse):
    """
    FUSE subclass

    Implements all the proxying of FUSE calls to 9p
    server. Can authomatically reconnect to the server.
    """
    def __init__(self, address, credentials, mountpoint,
            debug=False, timeout=10, keep_reconnect=False):
        """
         * address -- (address,port) of the 9p server, tuple
         * credentials -- py9p.Credentials
         * mountpoint -- where to mount the FS
         * debug -- FUSE and py9p debug output, implies foreground run
         * timeout -- socket timeout
         * keep_reconnect -- whether to try reconnect after errors
        """

        self.address = address
        self.credentials = credentials
        self.debug = debug
        self.timeout = timeout
        self.msize = 1024 * 16
        self.sock = None
        self.exit = None
        self.dotu = 1
        self.keep_reconnect = keep_reconnect
        self._lock = threading.Lock()
        self._interval = 1
        self._reconnect_event = threading.Event()
        self._connected_event = threading.Event()
        self._reconnect(init=True)
        self.dircache = {}
        self.fidcache = FidCache()
        self.tfidcache = FidCache(start=MIN_TFID, limit=MAX_TFID)

        fuse.Fuse.__init__(self, version="%prog " + fuse.__version__,
                dash_s_do='undef')

        if debug:
            self.fuse_args.setmod('foreground')
            self.fuse_args.add('debug')
        self.fuse_args.add('large_read')
        self.fuse_args.add('big_writes')
        self.fuse_args.mountpoint = os.path.realpath(mountpoint)

    def fsinit(self):
        # daemon mode RNG hack for PyCrypto
        try:
            from Crypto import Random
            Random.atfork()
        except:
            pass

    def _reconnect(self, init=False, dotu=1):
        """
        Start reconnection thread. When init=True, just probe
        the connection and return even if keep_reconnect=True.
        """
        if self._lock.acquire(False):
            self._connected_event.clear()
            t = threading.Thread(
                    target=self._reconnect_target,
                    args=(init, dotu))
            t.setDaemon(True)
            t.start()
            if init:
                # in the init state we MUST NOT leave
                # any thread; all running threads will be
                # suspended by FUSE in the "daemon"
                # multithreaded mode
                t.join()
            else:
                # otherwise, just run reconnection
                # thread in the background
                self._connected_event.wait(self.timeout + 2)
            if self.exit:
                print(str(self.exit))
                sys.exit(255)

    def _reconnect_interval(self):
        """
        Return next reconnection interval in seconds.
        """
        self._interval = min(self._interval * 2, MAX_RECONNECT_INTERVAL)
        return self._interval

    def _reconnect_target(self, init=False, dotu=1):
        """
        Reconnection thread code.
        """
        while True:
            try:
                self.sock.close()
            except:
                pass

            try:
                if self.debug:
                    print("trying to connect")
                if self.address[0].find("/") > -1:
                    self.sock = socket.socket(socket.AF_UNIX)
                else:
                    self.sock = socket.socket(socket.AF_INET)
                self.sock.settimeout(self.timeout)
                self.sock.connect(self.address)
                self.client = py9p.Client(
                        fd=self.sock,
                        chatty=self.debug,
                        credentials=self.credentials,
                        dotu=dotu, msize=self.msize)
                self.msize = self.client.msize
                self._connected_event.set()
                self._lock.release()
                return
            except py9p.VersionError:
                if dotu:
                    self.dotu = 0
                    self._reconnect_target(init, 0)
                else:
                    self.exit = Exception("protocol negotiation error")
                return
            except Exception as e:
                if self.keep_reconnect:
                    if init:
                        # if we get an error on the very initial
                        # time, just fake the connection --
                        # next reconnect round will be triggered
                        # by the next failed FS call
                        self._lock.release()
                        self._connected_event.set()
                        return
                    s = self._reconnect_interval()
                    if self.debug:
                        print("reconnect in %s seconds" % (s))
                    self._reconnect_event.wait(s)
                    self._reconnect_event.clear()
                else:
                    self.exit = e
                    self._lock.release()
                    self._connected_event.set()
                    return

    @guard
    def open(self, tfid, path, mode):
        f = self.fidcache.acquire()
        try:
            self.client._walk(self.client.ROOT,
                    f.fid, filter(None, path.split("/")))
            self.client._open(f.fid, py9p.open2plan(mode))
            return f
        except:
            self.fidcache.release(f)
            return -errno.EIO

    @guard
    def _wstat(self, tfid, path,
            uid=py9p.ERRUNDEF,
            gid=py9p.ERRUNDEF,
            mode=py9p.ERRUNDEF):
        self.client._walk(self.client.ROOT,
                tfid, filter(None, path.split("/")))
        if self.dotu:
            stats = [py9p.Dir(
                dotu=1,
                type=0,
                dev=0,
                qid=py9p.Qid(0, 0, py9p.hash8(path)),
                mode=mode,
                atime=int(time.time()),
                mtime=int(time.time()),
                length=py9p.ERRUNDEF,
                name=path.split("/")[-1],
                uid="",
                gid="",
                muid="",
                extension="",
                uidnum=uid,
                gidnum=gid,
                muidnum=py9p.ERRUNDEF), ]
        else:
            stats = [py9p.Dir(
                dotu=0,
                type=0,
                dev=0,
                qid=py9p.Qid(0, 0, py9p.hash8(path)),
                mode=mode,
                atime=int(time.time()),
                mtime=int(time.time()),
                length=py9p.ERRUNDEF,
                name=path.split("/")[-1],
                uid=pwd.getpwuid(uid).pw_name,
                gid=grp.getgrgid(gid).gr_name,
                muid=""), ]
        self.client._wstat(tfid, stats)
        self.client._clunk(tfid)

    def chmod(self, path, mode):
        return self._wstat(path, mode=py9p.mode2plan(mode))

    def chown(self, path, uid, gid):
        return self._wstat(path, uid, gid)

    def utime(self, path, times):
        pass

    @guard
    def unlink(self, tfid, path):
        self.client._walk(self.client.ROOT,
                tfid, filter(None, path.split("/")))
        self.client._remove(tfid)
        self.dircache = {}

    def rmdir(self, path):
        self.unlink(path)

    @guard
    def symlink(self, tfid, target, path):
        if not self.dotu:
            return -errno.ENOSYS
        self.client._walk(self.client.ROOT, tfid,
                filter(None, path.split("/"))[:-1])
        self.client._create(tfid, filter(None, path.split("/"))[-1],
                py9p.DMSYMLINK, 0, target)
        self.client._clunk(tfid)

    @guard
    def mknod(self, tfid, path, mode, dev):
        if dev != 0:
            return -errno.ENOSYS
        # FIXME
        if not mode & stat.S_IFREG:
            mode |= stat.S_IFDIR
        try:
            self.client._walk(self.client.ROOT,
                    tfid, filter(None, path.split("/")))
            self.client._open(tfid, py9p.OTRUNC)
            self.client._clunk(tfid)
        except py9p.RpcError as e:
            if e.message == "file not found":
                    self.client._walk(self.client.ROOT,
                            tfid, filter(None, path.split("/"))[:-1])
                    self.client._create(tfid,
                            filter(None, path.split("/"))[-1],
                            py9p.mode2plan(mode), 0)
                    self.client._clunk(tfid)
            else:
                return -errno.EIO

    def mkdir(self, path, mode):
        return self.mknod(path, mode | stat.S_IFDIR, 0)

    @guard
    def truncate(self, tfid, path, size):
        if size != 0:
            return -errno.ENOSYS
        self.client._walk(self.client.ROOT,
                tfid, filter(None, path.split("/")))
        self.client._open(tfid, py9p.OTRUNC)
        self.client._clunk(tfid)

    @guard
    def write(self, tfid, path, buf, offset, f):
        l = len(buf)
        for i in range(l / self.msize + 1):
            start = i * self.msize
            length = self.msize + min(0, (l - ((i + 1) * self.msize)))
            self.client._write(f.fid, offset + start, buf[start:length])
        return l

    @guard
    def read(self, tfid, path, size, offset, f):
        data = bytes()
        for i in range(size / self.msize + 1):
            ret = self.client._read(f.fid, offset, self.msize)
            data += ret.data
            offset += len(ret.data)
        return data[:size]

    @guard
    def release(self, tfid, path, flags, f):
        try:
            self.client._clunk(f.fid)
            self.fidcache.release(f)
        except:
            pass

    @guard
    def readlink(self, tfid, path):
        if py9p.hash8(path) in self.dircache:
            return self.dircache[py9p.hash8(path)].extension
        self.client._walk(self.client.ROOT,
                tfid, filter(None, path.split("/")))
        self.client._open(tfid, py9p.OREAD)
        ret = self.client._read(tfid, 0, self.msize)
        self.client._clunk(tfid)
        return ret.data

    @guard
    def _getattr(self, tfid, path):
        if py9p.hash8(path) in self.dircache:
            return fStat(self.dircache[py9p.hash8(path)])
        try:
            self.client._walk(self.client.ROOT,
                    tfid, filter(None, path.split("/")))
            ret = self.client._stat(tfid).stat[0]
        except py9p.RpcError as e:
            if e.message == "file not found":
                return -errno.ENOENT
            else:
                return -errno.EIO
        s = fStat(ret)
        self.client._clunk(tfid)
        self.dircache[py9p.hash8(path)] = ret
        return s

    def getattr(self, path):
        self._interval = 1
        self._reconnect_event.set()

        s = self._getattr(path)

        if s == -errno.EIO:
            if self.keep_reconnect:
                if path == "/":
                    return fakeRoot()
                else:
                    return -errno.ENOENT
        return s

    @guard
    def _readdir(self, tfid, path, offset):
        dirs = []
        self.client._walk(self.client.ROOT,
                tfid, filter(None, path.split("/")))
        self.client._open(tfid, py9p.OREAD)
        offset = 0
        while True:
            ret = self.client._read(tfid, offset, self.msize)
            if len(ret.data) == 0:
                break
            offset += len(ret.data)
            p9 = marshal9p.Marshal9P(dotu=self.dotu)
            p9.setBuf(ret.data)
            fcall = py9p.Fcall(py9p.Rstat)
            p9.decstat(fcall, 0)
            dirs.extend(fcall.stat)
        self.client._clunk(tfid)
        return dirs

    def readdir(self, path, offset):
        self._interval = 1
        self._reconnect_event.set()

        dirs = self._readdir(path, offset)
        if dirs == -errno.EIO:
            dirs = []

        if path == "/":
            path = ""
        for i in dirs:
            self.dircache[py9p.hash8("/".join((path, i.name)))] = i
            yield fuse.Direntry(i.name)
