#!/usr/bin/env python
import time
import sys
import getopt
import os
import copy
import py9p

import getopt
import getpass

class SampleFs(py9p.Server):
    """
    A sample plugin filesystem.
    """
    mountpoint = '/'
    root = None
    files = {}
    def __init__(self):
        self.start = int(time.time())
        rootdir = py9p.Dir(0)    # not dotu
        rootdir.children = []
        rootdir.type = 0
        rootdir.dev = 0
        rootdir.mode = 0755
        rootdir.atime = rootdir.mtime = int(time.time())
        rootdir.length = 0
        rootdir.name = '/'
        rootdir.uid = rootdir.gid = rootdir.muid = os.environ['USER']
        rootdir.qid = py9p.Qid(py9p.QTDIR, 0, py9p.hash8(rootdir.name))
        rootdir.parent = rootdir
        self.root = rootdir    # / is its own parent, just so we don't fall off the edge of the earth

        # two files in '/'
        f = copy.copy(rootdir)
        f.name = 'sample1'
        f.qid = py9p.Qid(0, 0, py9p.hash8(f.name))
        f.length = 1024
        f.parent = rootdir
        self.root.children.append(f)
        f = copy.copy(f)
        f.name = 'sample2'
        f.length = 8192
        f.qid = py9p.Qid(0, 0, py9p.hash8(f.name))
        self.root.children.append(f)

        self.files[self.root.qid.path] = self.root
        for x in self.root.children:
            self.files[x.qid.path] = x

    def open(self, srv, req):
        '''If we have a file tree then simply check whether the Qid matches
        anything inside. respond qid and iounit are set by protocol'''
        if not self.files.has_key(req.fid.qid.path):
            srv.respond(req, "unknown file")
        f = self.files[req.fid.qid.path]
        if (req.ifcall.mode & f.mode) != py9p.OREAD :
            raise py9p.ServerError("permission denied")
        srv.respond(req, None)

    def walk(self, srv, req):
        # root walks are handled inside the protocol if we have self.root
        # set, so don't do them here. '..' however is handled by us,
        # trivially

        f = self.files[req.fid.qid.path]
        if len(req.ifcall.wname) > 1:
            srv.respond(req, "don't know how to handle multiple walks yet")
            return

        if req.ifcall.wname[0] == '..':
            req.ofcall.wqid.append(f.parent.qid)
            srv.respond(req, None)
            return

        for x in f.children:
            if req.ifcall.wname[0] == x.name:
                req.ofcall.wqid.append(x.qid)
                srv.respond(req, None)
                return

        srv.respond(req, "can't find %s"%req.ifcall.wname[0])
        return

    def read(self, srv, req):
        if not self.files.has_key(req.fid.qid.path):
            raise py9p.ServerError("unknown file")

        f = self.files[req.fid.qid.path]
        if f.qid.type & py9p.QTDIR:
            req.ofcall.stat = []
            for x in f.children:
                req.ofcall.stat.append(x)
        elif f.name == 'sample1':
            buf = '%d\n' % time.time()
            req.ofcall.data = buf[:req.ifcall.count]
        elif f.name == 'sample2' :
            buf = 'The time is now %s. thank you for asking.\n' % time.asctime(time.localtime(time.time()))
            if req.ifcall.offset > len(buf):
                req.ofcall.data = ''
            else:
                req.ofcall.data = buf[req.ifcall.offset : req.ifcall.offset + req.ifcall.count]

        srv.respond(req, None)

def usage(argv0):
    print "usage:  %s [-dD] [-p port] [-l listen] [-a authmode] [srvuser domain]" % argv0
    sys.exit(1)

def main(prog, *args):
    listen = 'localhost'
    port = py9p.PORT
    mods = []
    noauth = 0
    dbg = False
    user = None
    dom = None
    passwd = None
    authmode = None
    key = None
    dotu = 0

    try:
        opt,args = getopt.getopt(args, "dDp:l:a:")
    except Exception, msg:
        usage(prog)
    for opt,optarg in opt:
        if opt == '-d':
            dotu = optarg
        if opt == "-D":
            dbg = True
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
        print >>sys.stderr, "unknown auth type: %s; accepted: pki or sk1"%authmode
        sys.exit(1)

    srv = py9p.Server(listen=(listen, port), authmode=authmode, user=user, dom=dom, key=key, chatty=dbg)
    srv.mount(SampleFs())
    srv.serve()


if __name__ == "__main__" :
    try :
        main(*sys.argv)
    except KeyboardInterrupt :
        print "interrupted."
