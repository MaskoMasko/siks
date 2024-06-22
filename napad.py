import itertools
import string
import crypt
import time
import sys

def provjera(niz):
    f1= open('users-passwords.conf', 'r')
    for i in f1:
        if i == niz + '\n':
            print('Uspjesno: ', i)
            return 1
    f1.close()


def brute_force(min_lenght=1, max_length=9):

    start_time = time.time()
    chars=string.digits + string.ascii_letters
    pokusaj = 0
    for password_length in range(min_lenght, max_length):
        for pogodi in itertools.product(chars, repeat=password_length):
            pokusaj += 1
            pogodi = ''.join(pogodi)

            salt='$6$0lgLWJet.bw0sMIq'
            sifra = crypt.crypt(pogodi, salt)
            niz = 'imagine '+ sifra
            if provjera(niz) == 1:
                print(round(time.time()-start_time, 2), 's')
                sys.exit()
            print(pogodi, 'pokusaj: ', pokusaj)
        

brute_force()



