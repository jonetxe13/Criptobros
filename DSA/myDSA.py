#!/usr/bin/env python3

import secrets, hashlib

class DSA:
    '''
    Reads and writes DSA keys from/to files (just 1024 bits long).
    The hash of the messages is computed with SHA-1.
    '''
    @classmethod
    def int2hex(cls, num, length=None):
        '''
        Returns a string representing the hexadecimal code of num.
        If length is set, leading zero bytes are added as needed.
        '''
        if length:
            length *= 2
            return '{:0{length}x}'.format(num, length=length)
        else:
            return format(num, 'x')
    
    def __init__(self, p=None, q=None, alpha=None, beta=None, d=None):
        '''
        Sets the initial parameters. The variable names follow the
        nomenclature in the book "Understanding Cryptograhy".
        p and q are the group and subgroup cardinalities.
        alpha is the generator.
        beta is the public/verification key.
        d is the private/signing key.
        '''
        self.p = p
        self.q = q
        self.alpha = alpha
        self.beta = beta
        self.d = 653633527604250031520881010531776565548374460673
    
    def read_publickey(self, filename):
        '''
        Read the system parameters and the public/verification key from a
        file.
        '''
        with open(filename, "rb") as f:
            line = f.readline()
            self.p = int(line, 16)
            line = f.readline()
            self.q = int(line, 16)
            line = f.readline()
            self.alpha = int(line, 16)
            line = f.readline()
            self.beta = int(line, 16)
    
    def calculate_private_key(dsa, signatures): 
        signature_pairs = [(sig >> 160, sig & ((1 << 160) - 1)) for sig in signatures]
        for i in range(len(signature_pairs)): 
            for j in range(i + 1, len(signature_pairs)): 
                if signature_pairs[i][0] == signature_pairs[j][0]: 
                    r = signature_pairs[i][0] 
                    s1, s2 = signature_pairs[i][1], signature_pairs[j][1]
                    with open(f"files/ipsum.txt", "rb") as f: m1 = f.read() 
                    with open(f"files/lorem.txt", "rb") as f: m2 = f.read()

                    H_m1 = int(hashlib.sha1(m1).hexdigest(), 16) 
                    H_m2 = int(hashlib.sha1(m2).hexdigest(), 16)

                    #calcular k
                    k = ((H_m1 - H_m2) * pow((s1 - s2), -1, dsa.q)) % dsa.q

                    x = ((s1 * k - H_m1) * pow(r, -1, dsa.q)) % dsa.q

                    return x
        return None

    def read_privatekey(self, filename):
        '''
        Read the private/signing key from a file.
        '''
        with open(filename, "rb") as f:
            line = f.readline()
            self.d = int(line, 16)

    def write_publickey(self, filename):
        '''
        Write the system parameters and the public/verification key to a
        file.
        '''
        if not self.p:
            raise Exception('Cannot write public key. Not set.')
        with open(filename, "wt") as f:
            f.write(self.int2hex(self.p) + '\n')
            f.write(self.int2hex(self.q) + '\n')
            f.write(self.int2hex(self.alpha) + '\n')
            f.write(self.int2hex(self.beta) + '\n')

    def write_privatekey(self, filename):
        '''
        Write the private/signing key to a file.
        '''
        if not self.d:
            raise Exception('Cannot write private key. Not set.')
        with open(filename, "wt") as f:
            f.write(self.int2hex(self.d) + '\n')

    def sign(self, m):
        '''
        Sign a message, m.
        '''
        if not self.d:
            raise Exception('Cannot sign. Private key not set.')
        digest = hashlib.sha1(m).digest()
        h = int.from_bytes(digest, 'big')
        ke = secrets.randbelow(self.q - 1) + 1 # 0 is not a valid key
        r = pow(self.alpha, ke, self.p) % self.q
        s = ((h + self.d*r) * pow(ke, -1, self.q)) % self.q
        
        return (r << 160) + s
    
    def verify(self, m, signature):
        '''
        Verify a signature.
        '''
        if not self.p:
            raise Exception('Cannot verify. Public key not set.')
        
        r = signature >> 160
        s = signature & ((1 << 160) - 1)
        
        if not (0 < r < self.q) or not (0 < s < self.q):
            return False
        
        digest = hashlib.sha1(m).digest()
        h = int.from_bytes(digest, 'big')
        
        w = pow(s, -1, self.q)
        u1 = (h * w) % self.q
        u2 = (r * w) % self.q
        v = ((pow(self.alpha, u1, self.p) * pow(self.beta, u2, self.p)) % self.p) % self.q
        
        return v == r
