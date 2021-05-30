import numpy as np
import random
import string
import time


def rol(val, r_bits, max_bits):
    res = (val << r_bits % max_bits) & (2**max_bits-1)
    res |= ((val & (2**max_bits-1)) >> (max_bits-(r_bits % max_bits)))
    return res


def ror(val, r_bits, max_bits):
    res = ((val & (2**max_bits-1)) >> r_bits % max_bits)
    res |= (val << (max_bits-(r_bits % max_bits)) & (2**max_bits-1))
    return res


class ModifiedPlayfair:
    def __init__(self, key):
        self.key = key
        self.key_mat = np.zeros((16, 16), dtype=int)
        self.key_mat = self.generate_key_mat(self.key, self.key_mat)

    @staticmethod
    def generate_key_mat(key, key_mat):
        byte_key = bytes(key, 'utf-8')
        new_val_list = list()
        for byte in byte_key:
            # print('Byte:', byte)
            # high_n = byte >> 4
            # low_n = byte & 0x0F
            # print('Before rot high,low:', high_n, ', ', low_n)
            # high_n = rol(high_n, 1, 4)
            # low_n = rol(low_n, 1, 4)
            # print('After rot high,low:', high_n, ', ', low_n)
            # new_byte = high_n + low_n
            new_byte = rol(byte, 2, 8)
            # print('New byte:', new_byte)
            if new_byte not in new_val_list:
                new_val_list.append(new_byte)
        val_list = list()
        val_list.extend(new_val_list)
        total_list = [i for i in range(256)]
        random.seed(256)
        random.shuffle(total_list)
        for num in total_list:
            if num not in new_val_list:
                val_list.append(num)
        i, j = 0, 0
        for val in val_list:
            if i < 16 and j < 16:
                key_mat[i][j] = val
                j += 1
                if j > 15:
                    j = 0
                    i += 1
            else:
                break

        return key_mat

    @staticmethod
    def get_loc(key_mat, val):
        return [int(i) for i in (np.where(key_mat == val))]

    def get_key_mat(self):
        return self.key_mat

    def encrypt(self, msg):
        t_start = time.time()
        byte_msg = bytes(msg, 'utf-8')
        # print('\nPlaintext in bytes :', byte_msg)
        byte_msg_len = len(byte_msg)
        # print('Len of byte_msg :', byte_msg_len)
        d = b'00000000'
        if byte_msg_len % 2:
            byte_msg += d
        i = 1

        encrypt_msg = b''

        while i <= byte_msg_len:
            a = rol(byte_msg[i-1], 2, 8)
            b = ror(byte_msg[i], 2, 8)
            print('A :', a, ' ,B:', b)
            a_loc_x, a_loc_y = self.get_loc(self.key_mat, a)
            b_loc_x, b_loc_y = self.get_loc(self.key_mat, b)

            print('A loc :', a_loc_x, a_loc_y)
            print('B loc :', b_loc_x, b_loc_y)

            if a_loc_x == b_loc_x:
                ra = self.key_mat[a_loc_x][(a_loc_y+1) % 16]
                rb = self.key_mat[b_loc_x][(b_loc_y+1) % 16]
            elif a_loc_y == b_loc_y:
                ra = self.key_mat[(a_loc_x+1) % 16][a_loc_y]
                rb = self.key_mat[(b_loc_x+1) % 16][b_loc_y]
            else:
                ra = self.key_mat[a_loc_x][b_loc_y]
                rb = self.key_mat[b_loc_x][a_loc_y]

            print('RA :', ra, 'RB :', rb)
            ra = int(ra)
            rb = int(rb)
            # rc = ra ^ rb
            ra = ra.to_bytes(1, 'big')
            rb = rb.to_bytes(1, 'big')
            encrypt_msg += ra + rb
            # print('For shuffle seed :', rc)
            # random.seed(chr(rc))
            # np.random.shuffle(self.key_mat)
            i += 2

        t_end = time.time()
        print("Time taken for encryption for size {} : {} s".format(byte_msg_len, (t_end-t_start)))
        return encrypt_msg

    def decrypt(self, encrypt_msg):
        t_start = time.time()
        encrypt_msg_len = len(encrypt_msg)

        original_msg = ''
        i = 1
        while i <= encrypt_msg_len:
            a = encrypt_msg[i-1]
            b = encrypt_msg[i]
            print('A:', a, 'B:', b)
            a_loc_x, a_loc_y = self.get_loc(self.key_mat, a)
            b_loc_x, b_loc_y = self.get_loc(self.key_mat, b)

            print('A loc :', a_loc_x, a_loc_y)
            print('B loc :', b_loc_x, b_loc_y)

            if a_loc_x == b_loc_x:
                ra = self.key_mat[a_loc_x][(a_loc_y-1) % 16]
                rb = self.key_mat[b_loc_x][(b_loc_y-1) % 16]
            elif a_loc_y == b_loc_y:
                ra = self.key_mat[(a_loc_x-1) % 16][a_loc_y]
                rb = self.key_mat[(b_loc_x-1) % 16][b_loc_y]
            else:
                ra = self.key_mat[a_loc_x][b_loc_y]
                rb = self.key_mat[b_loc_x][a_loc_y]

            print('RA :', ra, 'RB :', rb)
            # c = a ^ b
            # print('For shuffle seed :', c)
            # random.seed(chr(c))
            # np.random.shuffle(self.key_mat)
            # original_msg += chr(ra) + chr(rb)
            original_msg += chr(ror(ra, 2, 8)) + chr(rol(rb, 2, 8))
            i += 2

        if original_msg[-1] == '0':
            original_msg = original_msg[:-1]

        t_end = time.time()
        print("Time taken for decryption for size {} : {} s".format(encrypt_msg_len, (t_end-t_start)))
        return original_msg


if __name__ == '__main__':
    plaintext_chars = string.printable
    possible_chars = string.ascii_letters + string.digits + string.punctuation
    length = 20
    # seed_no = 154
    # random.seed(seed_no)
    plaintext = ''.join(random.choice(plaintext_chars) for i in range(length))
    # random.seed(171)
    length = 256
    key = ''.join(random.choice(possible_chars) for i in range(length))
    print('Plaintext :', plaintext)
    print('Key :', key)
    print('\nEncryption process:\n')
    obj = ModifiedPlayfair(key)
    print('Initial Key Matrix:\n', obj.get_key_mat())
    emsg = obj.encrypt(plaintext)
    print('\nEncrypted text:', emsg)

    print('\nDecryption process:\n')
    obj2 = ModifiedPlayfair(key)
    print('Initial Key Matrix:\n', obj.get_key_mat())
    omsg = obj2.decrypt(emsg)
    print('Decrypted text :', omsg)

    if plaintext == omsg:
        print('Successfully decrypted : plaintext == decrypted msg')
    else:
        print('Failure in process : plaintext != decrypted msg')
        '''
        print('\nDisplaying mismatched values:-')
        for i in plaintext:
            for j in omsg:
                if i != j:
                    print(i,j)
        '''
