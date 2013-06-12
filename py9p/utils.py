import sys

if sys.version_info[0] == 2:
    def bytes3(x):
        if isinstance(x, unicode):
            return bytes(x.encode('utf-8'))
        else:
            return bytes(x)
else:
    def bytes3(x):
        return bytes(x, 'utf-8')


