#!/usr/local/bin/python
#  -*- coding: utf-8 -*-

# heb - convert and print Hebrew encoded as ASCII 0xA0-
# Written with the kind help of Tomer Zait

import argparse

heb_letters = [ch - 0xA0 for ch in range(ord(u'א'), ord(u'ת') + 1)]


def conv(ch):
    if (ch < 0xA0) or (ch > 0xBA):
        return chr(ch)
    else:
        return chr(heb_letters[0] + ch)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Weird hebrew translator')
    parser.add_argument('translate', metavar='N', type=lambda c: int(c, 16), nargs='+',
                        help='A hex array to translate')

    args = parser.parse_args()
    print("\"%s\"" % u"".join(map(lambda o: conv(o), args.translate)))
