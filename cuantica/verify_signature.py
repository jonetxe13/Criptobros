#!/usr/bin/env python3

import sys, os
from myOTS import LD_OTS

TOVERIFY=os.path.join('files','lorem.pdf')
PUBLICKEY_FILENAME='public'

def main(signature_filename):
    ots = LD_OTS()
    ots.loadPublic(PUBLICKEY_FILENAME)
    signature = LD_OTS.loadSignature(signature_filename)

    with open(TOVERIFY, 'rb') as f:
        data = f.read()
    if ots.verify(data, signature):
        print('Valid signature.')
    else:
        print('Invalid signature.')

if __name__ == '__main__':
	if len(sys.argv) != 2:
		print('You must specify the signature file name as the only argument to the script.')
	else:
		main(sys.argv[1])
