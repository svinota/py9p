"""
Implementation of the p9sk1 authentication.

This module requires the Python Cryptography Toolkit from
http://www.amk.ca/python/writing/pycrypt/pycrypt.html
"""

import socket
import random
from Crypto.Cipher import DES

import py9p
import marshal9p


class Error(py9p.Error):
    pass


class AuthError(Error):
    pass


class AuthsrvError(Error):
    pass


class ServError(Error):
    pass

TickReqLen = 141
TickLen = 72
AuthLen = 13

AuthTreq, AuthChal, AuthPass, AuthOK, AuthErr, AuthMod = range(1, 7)
AuthTs, AuthTc, AuthAs, AuthAc, AuthTp, AuthHr = range(64, 70)

AUTHPORT = 567


def pad(str, l, padch='\0'):
    str += padch * (l - len(str))
    return str[:l]

par = [0x01, 0x02, 0x04, 0x07, 0x08, 0x0b, 0x0d, 0x0e,
    0x10, 0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c, 0x1f,
    0x20, 0x23, 0x25, 0x26, 0x29, 0x2a, 0x2c, 0x2f,
    0x31, 0x32, 0x34, 0x37, 0x38, 0x3b, 0x3d, 0x3e,
    0x40, 0x43, 0x45, 0x46, 0x49, 0x4a, 0x4c, 0x4f,
    0x51, 0x52, 0x54, 0x57, 0x58, 0x5b, 0x5d, 0x5e,
    0x61, 0x62, 0x64, 0x67, 0x68, 0x6b, 0x6d, 0x6e,
    0x70, 0x73, 0x75, 0x76, 0x79, 0x7a, 0x7c, 0x7f,
    0x80, 0x83, 0x85, 0x86, 0x89, 0x8a, 0x8c, 0x8f,
    0x91, 0x92, 0x94, 0x97, 0x98, 0x9b, 0x9d, 0x9e,
    0xa1, 0xa2, 0xa4, 0xa7, 0xa8, 0xab, 0xad, 0xae,
    0xb0, 0xb3, 0xb5, 0xb6, 0xb9, 0xba, 0xbc, 0xbf,
    0xc1, 0xc2, 0xc4, 0xc7, 0xc8, 0xcb, 0xcd, 0xce,
    0xd0, 0xd3, 0xd5, 0xd6, 0xd9, 0xda, 0xdc, 0xdf,
    0xe0, 0xe3, 0xe5, 0xe6, 0xe9, 0xea, 0xec, 0xef,
    0xf1, 0xf2, 0xf4, 0xf7, 0xf8, 0xfb, 0xfd, 0xfe]


def expandKey(key):
    """Expand a 7-byte DES key into an 8-byte DES key"""
    k = map(ord, key)
    k64 = [k[0] >> 1,
            (k[1] >> 2) | (k[0] << 6),
            (k[2] >> 3) | (k[1] << 5),
            (k[3] >> 4) | (k[2] << 4),
            (k[4] >> 5) | (k[3] << 3),
            (k[5] >> 6) | (k[4] << 2),
            (k[6] >> 7) | (k[5] << 1),
            k[6] << 0]
    return "".join([chr(par[x & 0x7f]) for x in k64])


def newKey(key):
    return DES.new(expandKey(key), DES.MODE_ECB)


def lencrypt(key, l):
    """Encrypt a list of characters, returning a list of characters"""
    return list(key.encrypt("".join(l)))


def ldecrypt(key, l):
    return list(key.decrypt("".join(l)))


def makeKey(password):
    """
    Hash a password into a key.
    """
    password = password[:28 - 1] + '\0'
    n = len(password) - 1
    password = pad(password, 28, ' ')
    buf = list(password)
    while 1:
        t = map(ord, buf[:8])

        k = [(((t[i]) >> i) + (t[i + 1] << (8 - (i + 1))) & 0xff) for i
                in xrange(7)]
        key = "".join([chr(x) for x in k])
        if n <= 8:
            return key
        n -= 8
        if n < 8:
            buf[:n] = []
        else:
            buf[:8] = []
        buf[:8] = lencrypt(newKey(key), buf[:8])


def randChars(n):
    """
    XXX This is *NOT* a secure way to generate random strings!
    This should be fixed if this code is ever used in a serious manner.
    """
    return "".join([chr(random.randint(0, 255)) for x in xrange(n)])


class Marshal(marshal9p.Marshal):
    def __init__(self):
        self.ks = None
        self.kn = None

    def setKs(self, ks):
        self.ks = newKey(ks)

    def setKn(self, kn):
        self.kn = newKey(kn)

    def encrypt(self, n, key):
        """Encrypt the last n bytes of the buffer with weird chaining."""
        idx = len(self.bytes) - n
        n -= 1
        for dummy in xrange(n / 7):
            self.bytes[idx: idx + 8] = lencrypt(key, self.bytes[idx: idx + 8])
            idx += 7
        if n % 7:
            self.bytes[-8:] = lencrypt(key, self.bytes[-8:])

    def decrypt(self, n, key):
        """Decrypt the first n bytes of the buffer."""
        if key is None:
            return
        m = n - 1
        if m % 7:
            self.bytes[n - 8:n] = ldecrypt(key, self.bytes[n - 8:n])
        idx = m - m % 7
        for dummy in xrange(m / 7):
            idx -= 7
            self.bytes[idx: idx + 8] = ldecrypt(key, self.bytes[idx: idx + 8])

    def encPad(self, x, l):
        self.encX(pad(x, l))

    def decPad(self, l):
        x = self.decX(l)
        idx = x.find('\0')
        if idx >= 0:
            x = x[:idx]
        return x

    def encChal(self, x):
        self._checkLen(x, 8)
        self.encX(x)

    def decChal(self):
        return self.decX(8)

    def encTicketReq(self, x):
        type, authid, authdom, chal, hostid, uid = x
        self.enc1(type)
        self.encPad(authid, 28)
        self.encPad(authdom, 48)
        self.encChal(chal)
        self.encPad(hostid, 28)
        self.encPad(uid, 28)

    def decTicketReq(self):
        return [self.dec1(),
            self.decPad(28),
            self.decPad(48),
            self.decChal(),
            self.decPad(28),
            self.decPad(28)]

    def encTicket(self, x):
        num, chal, cuid, suid, key = x
        self._checkLen(key, 7)
        self.enc1(num)
        self.encChal(chal)
        self.encPad(cuid, 28)
        self.encPad(suid, 28)
        self.encX(key)
        self.encrypt(1 + 8 + 28 + 28 + 7, self.ks)

    def decTicket(self):
        self.decrypt(1 + 8 + 28 + 28 + 7, self.ks)
        return [self.dec1(),
            self.decChal(),
            self.decPad(28),
            self.decPad(28),
            self.decX(7)]

    def encAuth(self, x):
        num, chal, id = x
        self.enc1(num)
        self.encChal(chal)
        self.enc4(id)
        self.encrypt(1 + 8 + 4, self.kn)

    def decAuth(self):
        self.decrypt(1 + 8 + 4, self.kn)
        return [self.dec1(),
            self.decChal(),
            self.dec4()]

    def encTattach(self, x):
        tick, auth = x
        self._checkLen(tick, 72)
        self.encX(tick)
        self.encAuth(auth)

    def decTattach(self):
        return self.decX(72), self.decAuth()


def getTicket(con, sk1, treq):
    """
    Connect to the auth server and request a set of tickets.
    Con is an open handle to the auth server, sk1 is a handle
    to a sk1 marshaller with Kc set and treq is a ticket request.
    Return the (opaque) server ticket and the (decoded) client ticket.
    Raises an AuthsrvError on failure.
    """
    sk1.setBuf()
    sk1.encTicketReq(treq)
    con.send(sk1.getBuf())
    ch = con.recv(1)
    if ch == chr(5):
        err = con.recv(64)
        raise AuthsrvError(err)
    elif ch != chr(4):
        raise AuthsrvError("invalid reply type %r" % ch)
    ctick = con.recv(72)
    stick = con.recv(72)
    if len(stick) + len(ctick) != 72 * 2:
        raise AuthsrvError("short auth reply")
    sk1.setBuf(ctick)
    return sk1.decTicket(), stick


# this could be cleaner
def clientAuth(cl, fcall, user, Kc, authsrv, authport=567):
    CHc = randChars(8)
    sk1 = Marshal()
    sk1.setKs(Kc)
    pos = [0]
    gen = 0

    def rd(l):
        fc = cl._read(fcall.afid, pos[0], l)
        pos[0] += len(fc.data)
        return fc.data

    def wr(x):
        fc = cl._write(fcall.afid, pos[0], x)
        pos[0] += fc.count
        return fc.count

    # negotiate
    proto = rd(128)
    v2 = 0
    if proto[:10] == 'v.2 p9sk1@':
        v2 = 1
        proto = proto[4:]
    if proto[:6] != 'p9sk1@':
        raise AuthError("unknown protocol %r" % proto)
    wr(proto.replace("@", " ", 1))
    if v2:
        if rd(3) != 'OK\0':
            raise AuthError("v.2 protocol botch")

    # Tsession
    sk1.setBuf()
    sk1.encChal(CHc)
    wr(sk1.getBuf())

    # Rsession
    sk1.setBuf(rd(TickReqLen))
    treq = sk1.decTicketReq()
    if v2 and treq[0] == 0:        # kenfs is fast and loose with auth formats
        treq[0] = AuthTreq
    if treq[0] != AuthTreq:
        raise AuthError("bad server")
    CHs = treq[3]

    # request ticket from authsrv
    treq[-2], treq[-1] = user, user
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((authsrv, authport),)
    (num, CHs2, cuid, suid, Kn), stick = getTicket(s, sk1, treq)  # XXX catch
    s.close()
    if num != AuthTc or CHs != CHs2:
        raise AuthError("bad password for %s or bad auth server" % user)
    sk1.setKn(Kn)

    # Tattach
    sk1.setBuf()
    sk1.encTattach([stick, [AuthAc, CHs, gen]])
    wr(sk1.getBuf())

    sk1.setBuf(rd(AuthLen))
    num, CHc2, gen2 = sk1.decAuth()
    if num != AuthAs or CHc2 != CHc:            # XXX check gen2 for replay
        raise AuthError("bad server")
    return


class AuthFs(object):
    """
    A special file for performing p9sk1 authentication.  On completion
    of the protocol, suid is set to the authenticated username.
    """
    type = 'sk1'
    HaveProtos, HaveSinfo, HaveSauth, NeedProto, NeedCchal, NeedTicket, \
            Success = range(7)
    cancreate = 0

    def __init__(self, user, dom, key):
        self.sk1 = Marshal()
        self.user = user
        self.dom = dom
        self.ks = key

    def estab(self, fid):
        fid.CHs = randChars(8)
        fid.CHc = None
        fid.suid = None
        fid.treq = [AuthTreq, self.user, self.dom, fid.CHs, '', '']
        fid.phase = self.HaveProtos

    def read(self, srv, req):
        self.sk1.setBuf()
        if req.fid.phase == self.HaveProtos:
            req.fid.phase = self.NeedProto
            req.ofcall.data = "p9sk1@%s\0" % self.dom
            srv.respond(req, None)
            return
        elif req.fid.phase == self.HaveSinfo:
            req.fid.phase = self.NeedTicket
            self.sk1.encTicketReq(req.fid.treq)
            req.ofcall.data = self.sk1.getBuf()
            srv.respond(req, None)
            return
        elif req.fid.phase == self.HaveSauth:
            req.fid.phase = self.Success
            self.sk1.encAuth([AuthAs, req.fid.CHc, 0])
            req.ofcall.data = self.sk1.getBuf()
            srv.respond(req, None)
            return
        srv.respond(req, "unexpected phase")

    def write(self, srv, req):
        buf = req.ifcall.data

        self.sk1.setBuf(buf)
        if req.fid.phase == self.NeedProto:
            l = buf.index("\0")
            if l < 0:
                raise ServError("missing terminator")
            s = buf.split(" ")
            if len(s) != 2 or s[0] != "p9sk1" or s[1] != self.dom + '\0':
                raise ServError("bad protocol %r" % buf)
            req.fid.phase = self.NeedCchal
            req.ofcall.count = l + 1
            srv.respond(req, None)
            return
        elif req.fid.phase == self.NeedCchal:
            req.fid.CHc = self.sk1.decChal()
            req.fid.phase = self.HaveSinfo
            req.ofcall.count = 8
            srv.respond(req, None)
            return
        elif req.fid.phase == self.NeedTicket:
            self.sk1.setKs(self.ks)
            num, chal, cuid, suid, key = self.sk1.decTicket()
            if num != AuthTs or chal != req.fid.CHs:
                raise ServError("bad ticket")
            self.sk1.setKn(key)
            num, chal, id = self.sk1.decAuth()
            if num != AuthAc or chal != req.fid.CHs or id != 0:
                raise ServError("bad authentication for %s" % suid)
            req.fid.suid = suid
            req.fid.phase = self.HaveSauth
            req.ofcall.count = 72 + 13
            srv.respond(req, None)
            return
        raise ServError("unexpected phase")
