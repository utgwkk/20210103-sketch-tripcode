import re
import string
from crypt import crypt
from base64 import b64encode
from hashlib import sha1


def generate_trip(tripstr):
    '''
    >>> generate_trip('#istrip')
    u'\u25c6/WG5qp963c'
    >>> generate_trip('#ニコニコ')
    u'\u25c6pA8Bpf.Qvk'
    '''
    if len(tripstr[1:]) >= 12:
        mark = tripstr[0]
        if mark == '#' or mark == '$':
            m = re.match(r'^#([0-9a-fA-F]{16})([\./0-9A-Za-z]{0,2})$', tripstr)
            if m:
                trip = crypt(str(int(m.group(1))), m.group(2) + '..')[-10:]
            else:
                trip = '???'
        else:
            m = sha1(tripstr[1:])
            trip = b64encode(m.digest())[:12]
            trip = trip.replace('+', '.')
    else:
        tripkey = tripstr[1:]
        salt = (tripkey + 'H.')[1:3]
        salt = re.sub(r'[^\.-z]', '.', salt)
        salt = salt.translate(string.maketrans(':;<=>?@[\\]^_`', 'ABCDEFGabcdef'))
        trip = crypt(tripkey, salt)
        trip = trip[-10:]
    trip = '◆' + trip

    retval = unicode(trip, encoding='shift-jis')
    return retval


if __name__ == '__main__':
    import doctest
    doctest.testmod()
