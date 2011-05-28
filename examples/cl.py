#!/usr/bin/env python
import socket
import sys
import os
import getopt
import getpass
import code
import readline
import atexit
import fnmatch

import py9p

class Error(py9p.Error): pass

def _os(func, *args):
    try:
        return func(*args)
    except OSError,e:
        raise Error(e.args[1])
    except IOError,e:
        raise Error(e.args[1])

class HistoryConsole(code.InteractiveConsole):
    def __init__(self, locals=None, filename="<console>",
                 histfile=os.path.expanduser("~/.py9phist")):
        code.InteractiveConsole.__init__(self)
        self.init_history(histfile)

    def init_history(self, histfile):
        readline.parse_and_bind("tab: complete")
        if hasattr(readline, "read_history_file"):
            try:
                readline.read_history_file(histfile)
            except IOError:
                pass
            atexit.register(self.save_history, histfile)

    def save_history(self, histfile):
        readline.write_history_file(histfile)

    
class CmdClient(py9p.Client):
    def mkdir(self, pstr, perm=0755):
        self.create(pstr, perm|py9p.DMDIR)
        self.close()

    def cat(self, name, out=None):
        if out is None:
            out = sys.stdout
        if self.open(name) is None:
            return
        while 1:
            buf = self.read(self.msize)
            if len(buf) == 0:
                break
            out.write(buf)
        self.close()

    def put(self, name, inf=None):
        if inf is None:
            inf = sys.stdin
        try:
            self.open(name, py9p.OWRITE|py9p.OTRUNC)
        except:
            self.create(name)

        sz = self.msize
        while 1:
            buf = inf.read(sz)
            self.write(buf)
            if len(buf) < sz:
                break
        self.close()

    def _cmdwrite(self, args):
        if len(args) < 1:
            print "write: no file name"
        elif len(args) == 1:
            buf = ''
        else:
            buf = ' '.join(args[1:])

        name = args[0]
        x = self.open(name, py9p.OWRITE|py9p.OTRUNC)
        if x is None:
            return
        if buf != None:
            self.write(buf)
        self.close()

    def _cmdecho(self, args):
        if len(args) < 1:
            print "echo: no file name"
        elif len(args) == 1:
            buf = ''
        else:
            buf = ' '.join(args[1:])

        if buf[-1] != '\n':
            buf = buf+'\n'

        name = args[0]
        x = self.open(name, py9p.OWRITE|py9p.OTRUNC)
        if x is None:
            return
        self.write(buf)
        self.close()

    def _cmdstat(self, args):
        for a in args:
            stat = self.stat(a)
            print stat[0].tolstr()

    def _cmdls(self, args):
        long = 0
        if len(args) > 0 and args[0] == '-l':
            long = 1
            args[0:1] = []
        ret = self.ls(long, args)
        if ret:
            if long:
                print '\n'.join(ret)
            else:
                print ' '.join(ret)

    def _cmdcd(self, args):
        if len(args) != 1:
            print "usage: cd path"
            return
        if self.cd(args[0]):
            if args[0][0] == '/':
                self.path = os.path.normpath(args[0])
            else:
                self.path = os.path.normpath(self.path + "/" + args[0])
            

    def _cmdio(self, args):
        if len(args) != 1:
            print "usage: io path"
            return
        self.io(args[0])

    def _cmdcat(self, args):
        if len(args) != 1:
            print "usage: cat path"
            return
        self.cat(args[0])

    def _cmdmkdir(self, args):
        if len(args) != 1:
            print "usage: mkdir path"
            return
        self.mkdir(args[0])
    def _cmdget(self, args):
        if len(args) == 1:
            f, = args
            f2 = f.split("/")[-1]
        elif len(args) == 2:
            f,f2 = args
        else:
            print "usage: get path [localname]"
            return
        out = _os(file, f2, "wb")
        self.cat(f, out)
        out.close()
    def _cmdput(self, args):
        if len(args) == 1:
            f, = args
            f2 = f.split("/")[-1]
        elif len(args) == 2:
            f,f2 = args
        else:
            print "usage: put path [remotename]"
            return
        if f == '-':
            inf = sys.stdin
        else:
            inf = _os(file, f, "rb")
        self.put(f2, inf)
        if f != '-':
            inf.close()
    def _cmdpwd(self, args):
        if len(args) == 0:
            print os.path.normpath(self.path)
        else:
            print "usage: pwd"
    def _cmdrm(self, args):
        if len(args) == 1:
            self.rm(args[0])
        else:
            print "usage: rm path"
    def _cmdhelp(self, args):
        cmds = [x[4:] for x in dir(self) if x[:4] == "_cmd"]
        cmds.sort()
        print "commands: ", " ".join(cmds)
    def _cmdquit(self, args):
        self.done = 1
    _cmdexit = _cmdquit

    def _nextline(self):        # generator is cleaner but not supported in 2.2
        if self.cmds is None:
            #sys.stdout.write("9p> ")
            #sys.stdout.flush()
            #line = sys.stdin.readline()
            line = self.cons.raw_input("9p> ")
            if line != "":
                return line
        else:
            if self.cmds:
                x,self.cmds = self.cmds[0],self.cmds[1:]
                return x

    def completer(self, text, state):
        ret = None
        cmds = [x[4:] for x in dir(self) if x[:4] == "_cmd"]
        cmds.sort()

        line = readline.get_line_buffer()
        level = line.split()
        if (len(level) == 0) or (len(level) == 1 and line[-1] != ' '):
            # match commands
            if text == '' and state < len(cmds):
                ret = cmds[state]
            else:
                l = filter(lambda x: x.startswith(text), cmds)
                if len(l) > state:
                    ret = l[state]+' '
        elif len(level) == 2 or line[-1] == ' ':
            # match files
            if state == 0:
                self.lsfiles = self.ls()
                self.lsfiles.sort()
            ls = self.lsfiles
            if text == '' and state < len(cmds):
                ret = ls[state]
            else:
                l = filter(lambda x: x.startswith(text), ls)
                if len(l) > state:
                    ret = l[state]+' '
        return ret

    def cmdLoop(self, cmds):
        self.cons = HistoryConsole()
        cmdf = {}
        for n in dir(self):
            if n[:4] == "_cmd":
                cmdf[n[4:]] = getattr(self, n)

        self.done = 0
        if not cmds:
            cmds = None
        else:
            self.done = 1 # exit after running the commands
        self.cmds = cmds
        while 1:
            line = self._nextline()
            if line is None:
                continue
            args = filter(None, line.split(" "))
            if not args:
                continue
            cmd,args = args[0],args[1:]
            if cmd in cmdf:
                try:
                    cmdf[cmd](args)
                except py9p.Error,e:
                    print "%s error: %s" % (cmd, e.args[0])
                    if e.args[0] == 'client eof':
                        break
            else:
                sys.stdout.write("%s ?\n" % cmd)
            if self.done and not self.cmds:
                break

def usage(prog):
    print "usage: %s [-d] [-m authmode] [-a authsrv] [-k privkey] [user@]srv[:port] [cmd ...]" % prog
    sys.exit(1)
    
def main():
    prog = sys.argv[0]
    args = sys.argv[1:]
    port = py9p.PORT
    authsrv = None
    chatty = 0
    authmode = 'none'
    privkey = None

    if os.environ.has_key('USER'):
        user = os.environ['USER']
    try:
        opt,args = getopt.getopt(args, "da:u:p:m:k:")
    except:
        usage(prog)
    passwd = None

    for opt,optarg in opt:
        if opt == '-m':
            authmode = optarg
        if opt == '-a':
            authsrv = optarg
        if opt == '-d':
            chatty = 1
        if opt == "-p":
            port = int(optarg)        # XXX catch
        if opt == '-u':
            user = optarg
        if opt == '-k':
            privkey = optarg
    
    if len(args) < 1:
        print >>sys.stderr, "error: no server to connect to..."
        usage(prog)

    srvkey = args[0].split('@', 1)
    if len(srvkey) == 2:
        user = srvkey[0]
        srvkey = srvkey[1]
    else:
        srvkey = srvkey[0]

    srvkey = srvkey.split(':', 1)
    if len(srvkey) == 2:
        port = int(srvkey[1])
    srvkey = srvkey[0]

    srv = srvkey
    if chatty:
        print "connecting as %s to %s, port %d" % (user, srv, port)

    if authmode == 'sk1' and authsrv is None:
        print >>sys.stderr, "assuming %s is also auth server" % srv
        authsrv = srv

    cmd = args[1:]

    sock = socket.socket(socket.AF_INET)
    try:
        sock.connect((srv, port),)
    except socket.error,e:
        print "%s: %s" % (srv, e.args[1])
        return

    if authmode == 'sk1' and passwd is None:
        passwd = getpass.getpass()
    try:
        cl = CmdClient(py9p.Sock(sock, 0, chatty), authmode, user, passwd, authsrv, chatty, key=privkey)
        readline.set_completer(cl.completer)
        cl.cmdLoop(cmd)
    except py9p.Error,e:
        print e

#'''
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "interrupted."
    except EOFError:
        print "done."
    except Exception, m:
        print "unhandled exception: " + str(m.args)
        raise
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
