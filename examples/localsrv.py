#!/usr/bin/env python 

import sys
import socket
import stat
import os.path
import copy
import time
import pwd
import grp

import py9p

def _os(func, *args):
    try:
        return func(*args)
    except OSError,e:
        raise py9p.ServerError(e.args)
    except IOError,e:
        raise py9p.ServerError(e.args)

def _nf(func, *args):
    try:
        return func(*args)
    except py9p.ServerError,e:
        return

def uidname(u):
    try:
        return "%s" % pwd.getpwuid(u).pw_name
    except KeyError,e:
        return "%d" % u

def gidname(g):
    try:
        return "%s" % grp.getgrgid(g).gr_name
    except KeyError,e:
        return "%d" % g

class LocalFs(object):
    """
    A local filesystem device.
    """

    files={}
    def __init__(self, root, cancreate=0, dotu=0):
        self.dotu = dotu
        self.cancreate = cancreate 
        self.root = self.pathtodir(root)
        self.root.parent = self.root
        self.root.localpath = root
        self.files[self.root.qid.path] = self.root

    def getfile(self, path):
        if not self.files.has_key(path):
            return None
        return self.files[path]

    def pathtodir(self, f):
        '''Stat-to-dir conversion'''
        s = _os(os.lstat, f)
        u = uidname(s.st_uid)
        g = gidname(s.st_gid)
        res = s.st_mode & 0777
        type = 0
        ext = ""
        if stat.S_ISDIR(s.st_mode):
            type = type | py9p.QTDIR
            res = res | py9p.DMDIR
        qid = py9p.Qid(type, 0, py9p.hash8(f))
        if self.dotu:
            if stat.S_ISLNK(s.st_mode):
                ext = os.readlink(f)
                ext = os.path.join(os.path.dirname(f), ext)
            elif stat.S_ISCHR(s.st_mode):
                ext = "c %d %d" % (os.major(s.st_rdev), os.minor(s.st_rdev))
            elif stat.S_ISBLK(s.st_mode):
                ext = "b %d %d" % (os.major(s.st_rdev), os.minor(s.st_rdev))
            else:
                ext = ""

            return py9p.Dir(1, 0, s.st_dev, qid,
                res,
                int(s.st_atime), int(s.st_mtime),
                s.st_size, os.path.basename(f), u, gidname(s.st_gid), u,
                ext, s.st_uid, s.st_gid, s.st_uid)
        else:
            return py9p.Dir(0, 0, s.st_dev, qid,
                res,
                int(s.st_atime), int(s.st_mtime),
                s.st_size, os.path.basename(f), u, g, u)

    def open(self, srv, req):
        f = self.getfile(req.fid.qid.path)
        if not f:
            srv.respond(req, "unknown file")
            return
        if (req.ifcall.mode & 3) == py9p.OWRITE:
            if not self.cancreate:
                srv.respond(req, "read-only file server")
                return
            if req.ifcall.mode & py9p.OTRUNC:
                m = "wb"
            else:
                m = "r+b"        # almost
        elif (req.ifcall.mode & 3) == py9p.ORDWR:
            if not self.cancreate:
                srv.respond(req, "read-only file server")
                return
            if m & OTRUNC:
                m = "w+b"
            else:
                m = "r+b"
        else:                # py9p.OREAD and otherwise
            m = "rb"
        if not (f.qid.type & py9p.QTDIR):
            f.fd = _os(file, f.localpath, m)
        srv.respond(req, None)

    def walk(self, srv, req):
        f = self.getfile(req.fid.qid.path)
        if not f:
            srv.respond(req, 'unknown file')
            return
        npath = f.localpath
        for path in req.ifcall.wname:
            # normpath takes care to remove '.' and '..', turn '//' into '/'
            npath = os.path.normpath(npath + "/" + path)
            if len(npath) <= len(self.root.localpath):
                # don't let us go beyond the original root
                npath = self.root.localpath

            if path == '.' or path == '':
                req.ofcall.wqid.append(f.qid)
            elif path == '..':
                # .. resolves to the parent, cycles at /
                qid = f.parent.qid
                req.ofcall.wqid.append(qid)
                f = f.parent
            else:
                d = self.pathtodir(npath)
                nf = self.getfile(d.qid.path)
                if nf:
                    # already exists, just append to req
                    req.ofcall.wqid.append(d.qid)
                    f = nf
                elif os.path.exists(npath):
                    d.localpath = npath
                    d.parent = f
                    self.files[d.qid.path] = d
                    req.ofcall.wqid.append(d.qid)
                    f = d
                else:
                    srv.respond(req, "can't find %s"%path)
                    return

        req.ofcall.nwqid = len(req.ofcall.wqid)
        srv.respond(req, None)

    def remove(self, srv, req):
        f = self.getfile(req.fid.qid.path)
        if not f:
            srv.respond(req, 'unknown file')
            return
        if not self.cancreate:
            srv.respond(req, "read-only file server")
            return

        if f.qid.type & py9p.QTDIR:
            _os(os.rmdir, f.localpath)
        else:
            _os(os.remove, f.localpath)
        self.files[req.fid.qid.path] = None
        srv.respond(req, None)

    def create(self, srv, req):
        fd = None
        if not self.cancreate:
            srv.respond(req, "read-only file server")
            return
        if req.ifcall.name == '.' or req.ifcall.name == '..':
            srv.respond(req, "illegal file name")
            return

        f = self.getfile(req.fid.qid.path)
        if not f:
            srv.respond(req, 'unknown file')
            return
        name = f.localpath+'/'+req.ifcall.name
        if req.ifcall.perm & py9p.DMDIR:
            perm = req.ifcall.perm & (~0777 | (f.mode & 0777))
            _os(os.mkdir, name, req.ifcall.perm & ~(py9p.DMDIR))
        else:
            perm = req.ifcall.perm & (~0666 | (f.mode & 0666))
            _os(file, name, "w+").close()
            _os(os.chmod, name, perm)
            if (req.ifcall.mode & 3) == py9p.OWRITE:
                if req.ifcall.mode & py9p.OTRUNC:
                    m = "wb"
                else:
                    m = "r+b"        # almost
            elif (req.ifcall.mode & 3) == py9p.ORDWR:
                if m & OTRUNC:
                    m = "w+b"
                else:
                    m = "r+b"
            else:                # py9p.OREAD and otherwise
                m = "rb"
            fd = _os(open, name, m)

        d = self.pathtodir(name)
        d.parent = f
        self.files[d.qid.path] = d
        self.files[d.qid.path].localpath = name
        if fd:
            self.files[d.qid.path].fd = fd
        req.ofcall.qid = d.qid
        srv.respond(req, None)

    def clunk(self, srv, req):
        f = self.getfile(req.fid.qid.path)
        if not f:
            srv.respond(req, 'unknown file')
            return
        f = self.files[req.fid.qid.path]        
        if hasattr(f, 'fd') and f.fd is not None:
            f.fd.close()
            f.fd = None
        srv.respond(req, None)

    def stat(self, srv, req):
        f = self.getfile(req.fid.qid.path)
        if not f:
            srv.respond(req, "unknown file")
            return
        req.ofcall.stat.append(self.pathtodir(f.localpath))
        srv.respond(req, None)

    def read(self, srv, req):
        f = self.getfile(req.fid.qid.path)
        if not f:
            srv.respond(req, "unknown file")
            return

        if f.qid.type & py9p.QTDIR:
            # no need to add anything to self.files yet. wait until they walk to it
            l = os.listdir(f.localpath)
            l = filter(lambda x : x not in ('.','..'), l)
            req.ofcall.stat = []
            for x in l:
                req.ofcall.stat.append(self.pathtodir(f.localpath+'/'+x))
        else:
            f.fd.seek(req.ifcall.offset)
            req.ofcall.data = f.fd.read(req.ifcall.count)
        srv.respond(req, None)

    def write(self, srv, req):
        if not self.cancreate:
            srv.respond(req, "read-only file server")
            return

        f = self.getfile(req.fid.qid.path)
        if not f:
            srv.respond(req, "unknown file")
            return

        f.fd.seek(req.ifcall.offset)
        f.fd.write(req.ifcall.data)
        req.ofcall.count = len(req.ifcall.data)
        srv.respond(req, None)

def usage(prog):
    print >>sys.stderr, "usage:  %s [-dcD] [-p port] [-r root] [-l listen] [-a authmode] [srvuser domain]" % prog
    sys.exit(1)

def main():
    import getopt
    import getpass

    prog = sys.argv[0]
    args = sys.argv[1:]

    port = py9p.PORT
    listen = '0.0.0.0'
    root = '/'
    mods = []
    user = None
    noauth = 0
    chatty = 0
    cancreate = 0
    dotu = 0
    authmode = None
    dom = None
    passwd = None
    key = None

    try:
        opt,args = getopt.getopt(args, "dDcp:r:l:a:")
    except:
        usage(prog)
    for opt,optarg in opt:
        if opt == "-D":
            chatty = 1
        if opt == "-d":
            dotu = 1
        if opt == '-c':
            cancreate = 1
        if opt == '-r':
            root = optarg
        if opt == "-p":
            port = int(optarg)
        if opt == '-l':
            listen = optarg
        if opt == '-a':
            authmode = optarg

    if authmode == 'sk1':
        if len(args) != 2:
            print >>sys.stderr, 'missing user and authsrv'
            usage(prog)
        else:
            py9p.sk1 = __import__("py9p.sk1").sk1
            user = args[0]
            dom = args[1]
            passwd = getpass.getpass()
            key = py9p.sk1.makeKey(passwd)
    elif authmode == 'pki':
        py9p.pki = __import__("py9p.pki").pki
        user = 'admin'
    elif authmode != None and authmode != 'none':
        print >>sys.stderr, "unknown auth type: %s; accepted: pki, sk1, none"%authmode
        sys.exit(1)

    srv = py9p.Server(listen=(listen, port), authmode=authmode, user=user, dom=dom, key=key, chatty=chatty, dotu=dotu)
    srv.mount(LocalFs(root, cancreate, dotu))
    srv.serve()

#'''
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "interrupted."
'''
if __name__ == "__main__":
    import trace

    # create a Trace object, telling it what to ignore, and whether to
    # do tracing or line-counting or both.
    tracer = trace.Trace(
        ignoredirs=[sys.prefix, sys.exec_prefix],
        trace=1,
        count=1)

    # run the new command using the given tracer
    tracer.run('main()')
    # make a report, placing output in /tmp
    r = tracer.results()
    r.write_results(show_missing=True, coverdir="/tmp")
#'''
