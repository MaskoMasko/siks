from __future__ import print_function
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from termcolor import colored
# pip install termcolor
import sys
import crypt
import socket
import getpass
import configparser


def remotesh():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # citanje konfiguracije za klijenta
    config = configparser.ConfigParser()
    config.read('/home/martina/labosi_sig/zavrsni/remotesh.conf')
    config.sections()
    port = config["DEFAULT"]["Port"]
    port = int(port)
    adresa = config["DEFAULT"]["Adresa"]

    sock.connect((adresa, port))
    k_ime = input(colored("Upisi korisnicko ime: ", 'red'))
    ispis = colored('Upisi sifru za prijavu: ', 'red')
    sifra = getpass.getpass(prompt = ispis)
    salt = '$6$0lgLWJet.bw0sMIq'
    k_sifra = crypt.crypt(sifra, salt)

    """
    # klijent salje na provjeru korisnicko ime i sifru
    niz = k_ime + " " + k_sifra
    niz_e = niz.encode()
    sock.send(niz_e)

    # klijent prima odgovor o uspjesnoj prijavi
    primljeni_podaci = sock.recv(1024)
    primljeni_niz = primljeni_podaci.decode()
    print(primljeni_niz)
    print()
    """




    
    niz = (k_ime + " " + k_sifra).encode()
    config = configparser.ConfigParser()
    config.read('/home/martina/labosi_sig/zavrsni/remotesh.conf')
    config.sections()
    a = config["DEFAULT"]["javni"]

    with open(a, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )
    # enkripcija korisnickog imena i lozinke za slanje klijentu
    k_ime_sifra=public_key.encrypt(
        niz,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    sock.send(k_ime_sifra)


    primljeni_podaci = sock.recv(1024)
    primljeni_niz = primljeni_podaci.decode()
    if(primljeni_niz == 'logirani ste '):
        print(colored(primljeni_niz, 'grey', 'on_green'))
    else:
        print(colored(primljeni_niz, 'white', 'on_red'))
    print()






    if(primljeni_niz == 'logirani ste '):

        # kreiranje simetričnog kljuca za sifriranje u sesiji
        key = Fernet.generate_key()
        
        """
        config = configparser.ConfigParser()
        config.read('/home/martina/labosi_sig/zavrsni/remotesh.conf')
        config.sections()
        a = config["DEFAULT"]["javni"]

        #with open(a, "rb") as key_file:
        #    public_key = serialization.load_pem_public_key(
        #    key_file.read(),
        #    password = None,
        #)

        with open(a, "rb") as f:
            public_key = serialization.load_pem_public_key(
                f.read(), backend=default_backend()
            )
        """
        ciphertext=public_key.encrypt(
            key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # klijent salje simetricni kljuc kriptiran asimetricnim javnim kljucem
        sock.send(ciphertext)


        fkey = Fernet(key)

        while True:
            primi = sock.recv(1024)
            # klijent prima od posluzitelja prompt za upis naredbe
            primi_izlaz = fkey.decrypt(primi).decode()
            print()
            print(colored(primi_izlaz, 'cyan'), end= ' ')
            unos = input()
            if(unos == 'exit' or unos=='odjava'):
                # klijent salje naredbu
                unos_e = fkey.encrypt(unos.encode())
                sock.send(unos_e)

                # klijent prima od posluzitelja izlaz naredbe
                primi = sock.recv(1024)
                primi_izlaz = fkey.decrypt(primi).decode()

                print(colored('Izlaz naredbe: ', 'magenta'))
                print(primi_izlaz)
                sys.exit()
            elif (unos == 'kill -15' or unos == 'kill -TERM' or unos == 'kill -SIGTERM'):
                # klijent salje naredbu
                unos_e = fkey.encrypt(unos.encode())
                sock.send(unos_e)

                # klijent prima od posluzitelja izlaz naredbe
                primi = sock.recv(1024)
                primi_izlaz = fkey.decrypt(primi).decode()

                print(colored('Izlaz naredbe: ', 'magenta'))
                print(primi_izlaz)
                sys.exit()
            else:
                # klijent salje naredbu
                #unos_e = unos.encode()
                unos_e = fkey.encrypt(unos.encode())
                sock.send(unos_e)

                # klijent prima od posluzitelja izlaz naredbe
                print(colored('Izlaz naredbe: ', 'magenta'))
                primi = sock.recv(1024)
                #primi_izlaz = primi.decode()
                primi_izlaz = fkey.decrypt(primi).decode()
                print(primi_izlaz)
            provjera = input("Zelite li upisati jos jednu naredbu (d/n): ")
            odgovor = provjera.upper()
            if(odgovor != 'D'):
                # klijent salje naredbu
                unos_e = fkey.encrypt('exit'.encode())
                sock.send(unos_e)

                # klijent prima od posluzitelja izlaz naredbe
                primi = sock.recv(1024)
                primi_izlaz = fkey.decrypt(primi).decode()

                print(colored('Izlaz naredbe: ', 'magenta'))
                print(primi_izlaz)
                break
    else:
        # klijent salje naredbu
        unos_e = 'exit'.encode()
        sock.send(unos_e)

        # klijent prima od posluzitelja izlaz naredbe
        primi = sock.recv(1024)
        primi_izlaz = primi.decode()

    sock.close()




remotesh()

