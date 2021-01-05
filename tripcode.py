import re
from passlib.hash import des_crypt
from base64 import b64encode
from hashlib import sha1


def generate_trip(tripstr: str) -> str:
    '''
    >>> generate_trip('#istrip')
    '◆/WG5qp963c'
    >>> generate_trip('#ニコニコ')
    '◆pA8Bpf.Qvk'

    (from https://w.atwiki.jp/aaaaaaaaaasaaaa/pages/11.html)
    >>> generate_trip('#t%{rｼ)L,')
    '◆HAckEr.Tac'
    >>> generate_trip('#DRL諞Qq@')
    '◆AAAAAAAc.s'
    >>> generate_trip('#JM@/!詫8')
    '◆GoGoGO/Bos'
    >>> generate_trip('#s0ﾝX[aF-')
    '◆1uzee/wmbQ'
    >>> generate_trip('#ｩ.N避y承')
    '◆4/9.......'
    >>> generate_trip('#DRL諞Qq@')
    '◆AAAAAAAc.s'
    '''
    if len(tripstr[1:]) >= 12:
        mark = tripstr[0]
        if mark == '#' or mark == '$':
            m = re.match(r'^#([0-9a-fA-F]{16})([\./0-9A-Za-z]{0,2})$', tripstr)
            if m:
                trip = des_crypt.hash(bytes(int(m.group(1)), 'shift-jis'), salt=(m.group(2).encode('shift-jis') + b'..').decode('shift-jis'))[-10:]
            else:
                trip = '???'
        else:
            m = sha1(tripstr[1:])
            trip = b64encode(m.digest())[:12]
            trip = trip.replace('+', '.')
    else:
        tripkey = tripstr[1:]
        # treat as Shift-JIS bytes
        tripkey = bytes(tripkey, encoding='shift-jis')
        salt = (tripkey + b'H.')[1:3]
        salt = re.sub(rb'[^\.-z]', b'.', salt)
        salt = salt.translate(bytes.maketrans(b':;<=>?@[\\]^_`', b'ABCDEFGabcdef'))
        trip = des_crypt.hash(tripkey, salt=salt.decode('shift-jis'))
        trip = trip[-10:]
    trip = '◆' + trip

    return trip


if __name__ == '__main__':
    import doctest
    doctest.testmod()
