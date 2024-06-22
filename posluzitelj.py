from __future__ import print_function
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from termcolor import colored
# pip install termcolor
import re
import os
import sys
import time
import socket
import signal
import requests
import datetime
import threading
import configparser


def tim10():
    kucni = os.path.expanduser('~')
    # varijabla sa kućnim direktorijem korisnika
    lock = threading.Lock()
    #definiranje lokota
    barrier = threading.Barrier(4)
    # definiranje barijere za 4 dretve
    rezultat = 27270270260260260260

    def podijeli(p,g):
        """
        Oduzima kvadrat brojeva koji se nalaze u zadanom rasponu od početnog rezultata
        i međuiznose zapisuje u vanjsku datoteku

        Argumenti:
        p -- donja granica raspona u kojem se nalaze brojevi koji se kvadriraju i oduzimaju od početnog rezultata
        g -- gornja granica raspona u kojem se nalaze brojevi koji se kvadriraju i oduzimaju od početnog rezultata

        Vraća:
        None
        """
        global rezultat
        lock.acquire()
        # zaključavanje lokota pri ulasku u kritičnu sekciju
        for i in range(p,g):
            rezultat = rezultat - i*i
        lock.release()
        # otključavanje lokota pri ulasku u kritičnu sekciju
        otvori = os.path.join(kucni, "rez.txt")
        datoteka = open(otvori, 'a')
        datoteka.write(str(rezultat))
        datoteka.write('\n')
        datoteka.close()
        barrier.wait()
        # barijera koja čeka 4 dretve koje zatim istovremeno završavaju izvođenje
        return None

    def vrijeme(naredba):
        """
        Funkcija koja ispisuje vrijeme, statusni kod i izlaz naredbe kako je zadano u zadatku
        Podci koji se ispisuju u izlazu naredbe se ne ispisuju u funckiji nego 
        se ispisuju pozivom određene naredbe 

        Funkcija prima parametar naredba :
        naredba -- string koji klijent posljeduje posluzitelju, a oznacava naredbu koji je potrebno pokrenuti
        """
        y = datetime.datetime.now()
        vrijeme = y.strftime('%H:%M:%S')
        datum = y.strftime('%Y-%m-%d')
        print(colored('\nDatum i vrijeme: ','magenta'), datum, vrijeme)
        print(colored('Primljena naredba: ', 'magenta'), naredba)
        kod = requests.get('http://localhost')
        print(colored('Statusni kod: ', 'magenta'), kod.status_code)
        print(colored('Izlaz naredbe: ', 'magenta'))

    def salji_cli(izlaz_naredbe):
        # funkcija za slanje izlaza naredbe klijentu
        salji = fkey.encrypt(str(izlaz_naredbe).encode())
        clisock.send(salji)




    # PRVI ZADATAK
    t = time.ctime()
    print('Pozdrav, dobrodosli u program. (Trenutno vrijeme je:{})' .format(t))

    # DRUGI ZADATAK
    unos = 0
    povijest=[]
    while(unos!='exit' or unos!= 'odjava' or a[0]!='exit' or a[0]!='odjava'):
        print()
        print(colored('{}::{}::{}$' .format(os.getlogin(), os.uname()[1], os.getcwd()), 'cyan'), end='')
        salji_cli('{}::{}::{}$' .format(os.getlogin(), os.uname()[1], os.getcwd()))
        # posluzitelj prima naredbu od klijenta
        unos_p = clisock.recv(1024)
        unos = fkey.decrypt(unos_p).decode()

        povijest.append(unos)
        # upis trenutnog unosa u polje povijest
        while (not unos):
        # ako nema unosa, odn. unos = ENTER ispisuje se prompt i ceka ponovan unos
            print('{}::{}::{}$'.format(os.getlogin(), os.uname()[1], os.getcwd()), end='')
            unos = input()
            povijest.append(unos)
        if (unos == 'exit' or unos == 'odjava'):
        # provjera je li unos jednak 'exit' ili 'odjava'
            dat = os.path.join(kucni, ".pov")
            pisi = open(dat, 'w+')
            # otvaranje(stvaranje) datoteke za pisanje .pov
            for i in range(len(povijest)):
                pisi.write('{}\n' .format(povijest[i]))
                # upis povijesti u datoteku .pov
            pisi.close()
            # zatvaranje datoteke
            vrijeme(unos)
            salji_cli('Zavrsetak programa.')
            sys.exit('Završetak programa.')
        a = unos.split()
        # a je polje u koje se spremaju dijelovi unosa bez razmaka
        if(a[0]!= 'pwd' and a[0]!='ps' and a[0]!='echo' and a[0]!='rmdir' and a[0]!='mkdir' and a[0]!='date' and a[0]!='cd' and a[0]!='kill' and a[0]!='ls' and a[0]!='kvadrat'):
        # ako nisu unesene naredbe koje program podrzava ispisuju se poruke
            vrijeme(unos)
            salji_cli('Upisali ste nardbu koju ovaj program ne podrzava!''\nMolim Vas da pokusate ponovo')
            print('Upisali ste nardbu koju ovaj program ne podrzava!')
            print('Molim Vas da pokušate ponovo')
        elif (a[0] == 'pwd' or 'ps' or 'echo' or 'rmdir' or 'mkdir' or 'date' or 'cd' or 'kvadrat' or 'kill'):
        # if petlja ispituje tocnost unesene naredbe
            #pwd
            if (a[0]== 'pwd'):
                if(len(a)==1):
                # ako je duljina polja a=1 onda je unesena samo naredba
                    vrijeme(unos)
                    salji_cli(os.getcwd())
                    print(os.getcwd())
                    # ispis radnog direktorija
                else:
                    vrijeme(unos)
                    salji_cli('Naredba ne prima parametre ni argumente')
                    print('Naredba ne prima parametre ni argumente')
            #ps
            elif(a[0] == 'ps'):
                if (len(a) == 1):
                # ako je duljina polja a=1 onda je unesena samo naredba ps
                    vrijeme(unos)
                    salji_cli(os.getpid())
                    print(os.getpid())
                    # ispis PID-a trenutnog procesa
                else:
                    vrijeme(unos)
                    salji_cli('Naredba ps ne prima argumente ni parametre')
                    print('Naredba ps ne prima argumente ni parametre')
            #echo
            elif (a[0] == 'echo'):
                a.pop(0)
                niz = ''
                # izbacuje nulti element liste, točnije string 'echo'
                for i in a:
                # briše navodnike ukoliko su samostalni element liste, do čega bi došlo ako unesemo npr. echo Dva " Tri
                    if (i == "'" or i == '"'):
                        a.remove(i)
                if (len(a) >= 1):
                    vrijeme(unos)
                    for arg in a:
                        arg = re.sub("^[']", '', arg)
                        # zamjenjuje jednostruke navodnike na početku riječi praznim znakom
                        arg = re.sub("[']$", '', arg)
                        # zamjenjuje jednostruke navodnike na kraju riječi praznim znakom
                        arg = re.sub('^["]', "", arg)
                        # zamjenjuje dvostruke navodnike na početku riječi praznim znakom
                        arg = re.sub('["]$', "", arg)
                        # zamjenjuje dvostruke navodnike na kraju riječi praznim znakom
                        niz = niz + arg + " "
                        print(arg, end=" ")
                    salji_cli(niz)
                    print()
                else:
                    vrijeme(unos)
                    salji_cli("Naredba prima bar jedan argument")
                    print("Naredba prima bar jedan argument")

            #cd
            elif(a[0]=='cd'):
                if(len(a)==1):
                # ako je duljina polja a=1 onda je unesena samo naredba cd
                    os.chdir(os.environ['HOME'])
                    vrijeme(unos)
                    salji_cli('Radni direktorij je postao kucni direktorij.')
                    print('Radni direktorij je postao kućni direktorij.')
                    # mijenja radni direktorij u kucni direktorij
                elif(len(a)==2):
                # ako je duljina polja a=2 onda je uz naredbu cd uneseno jos nesto
                    if not os.path.exists(os.path.expanduser(a[1])):
                    # provjera je li poslije naredbe cd unesena ispravna adresa
                        vrijeme(unos)
                        salji_cli('Ova adresa na zalost ne postoji. Pokusajte sa nekom drugom adresom')
                        print('Ova adresa na zalost ne postoji. Pokusajte sa nekom drugom adresom')
                    else:
                        os.chdir(os.path.expanduser(a[1]))
                        vrijeme(unos)
                        salji_cli(os.path.expanduser(a[1]))
                        print('\n' + os.path.expanduser(a[1]))
                        # ako je unesena ispravana adresa onda je radni direktorij onaj zadan poslije naredbe
                else:
                    vrijeme(unos)
                    salji_cli('Naredba cd prima samo jedan argument. Unijeli ste previse argumenata')
                    print('Naredba cd prima samo jedan argument. Unijeli ste previse argumenata')
                    # spis pogreske jer je uneseno previse argumenata
            #date
            elif (a[0] == 'date'):
                if (len(a) == 1):
                    # ako je duljina polja a=1 onda je unesena samo naredba date
                    y = datetime.datetime.now()
                    # y = trenutno vrijeme
                    vrijeme1 = y.strftime('%I>%M>%S')
                    # od trenutnog vremena uzima sate (00-12), minute i sekunde
                    dan = y.strftime('%A')
                    # od trenutnog vremena uzima puni naziv dana u tjednu
                    datum = y.strftime('%d.%m.%Y')
                    # od trenutnog vremena uzima broj dana u mjesecu, mjesec (01-12) i godinu
                    vrijeme(unos)
                    salji_cli('{} {} {}'.format(vrijeme1, dan, datum))
                    print('{} {} {}'.format(vrijeme1, dan, datum))
                    # Ispisuje varijable vrijeme, dan ,datum
                elif(len(a) == 2):
                    # ako je duljina polja a=2 onda je uz naredbu date uneseno jos nesto
                    if (a[1] == '-s'):
                    # uz naredbu date unesen je parametar -s
                        y = datetime.datetime.now()
                        vrijeme1 = y.strftime('%H>%M>%S')
                        # od trenutnog vremena uzima sate (00-23), minute i sekunde
                        dan = y.strftime('%A')
                        # od trenutnog vremena uzima puni naziv dana u tjednu
                        datum = y.strftime('%d.%m.%Y')
                        # od trenutnog vremena uzima broj dana u mjesecu, mjesec (01-12) i godinu
                        vrijeme(unos)
                        salji_cli('{} {} {}'.format(vrijeme1, dan, datum))
                        print('{} {} {}'.format(vrijeme1, dan, datum))
                    else:
                        vrijeme(unos)
                        salji_cli('Naredba \'date\' prihvaca jedan parametar (-s) i ne prihvaca argumente')
                        print('Naredba \'date\' prihvaća jedan parametar (-s) i ne prihvaća argumente')
                        # ako je uz naredbu date uneseno bilo što osim -s ispisuje se poruka
                else:
                    vrijeme(unos)
                    salji_cli('Naredba \'date\' prihvaca najvise jedan parametar (-s) i ne prihvaca argumente')
                    print('Naredba \'date\' prihvaća najviše jedan parametar (-s) i ne prihvaća argumente')
                    # ako je uz naredbu date upisano više parametara ili argumenata ispisuje se poruka

            #rmdir
            elif(a[0]=='rmdir'):
                if (len(a) == 1):
                # provjera duljine polja a
                    vrijeme(unos)
                    salji_cli('Naredba rmdir mora imati jedan argument. Molim Vas da pokusate ponovo')
                    print('Naredba rmdir mora imati jedan argument. Molim Vas da pokusate ponovo')
                elif (len(a) == 2):
                # ako je duljina od polja a=2, slijedi provjera adrese argumenta koji je unesen nakon naredbe
                    if ((os.path.exists(os.path.expanduser(a[1])))==False):
                        vrijeme(unos)
                        salji_cli('Ova adresa na vodi do zeljenog direktorija. Pokusajte sa nekom drugom adresom')
                        print('Ova adresa na vodi do zeljenog direktorija. Pokusajte sa nekom drugom adresom')
                    else:
                        if(len(os.listdir(os.path.expanduser(a[1])))==0):
                        # ako je unesena tocna adresa koja vodi do direktorija ispituje se je li direktorij prazan
                            vrijeme(unos)
                            os.rmdir(os.path.expanduser(a[1]))
                            # brise se direktoji jer je prazan
                            if not os.path.exists(os.path.expanduser(a[1])):
                                salji_cli('Direktorij je obrisan')
                                print('Direktorij je obrisan')
                        else:
                            vrijeme(unos)
                            salji_cli('Brisanje nije moguce jer direktroij nije prazan!')
                            print('Brisanje nije moguce jer direktroij nije prazan!')
                else:
                    vrijeme(unos)
                    salji_cli('Naredba rmdir prima samo jedan argument. Unijeli ste previse argumenata')
                    print('Naredba rmdir prima samo jedan argument. Unijeli ste previse argumenata')
            #mkdir
            elif (a[0]=='mkdir'):
                if (len(a) == 1):
                    vrijeme(unos)
                    salji_cli('Naredba mkdir mora imati argument')
                    print('Naredba mkdir mora imati argument')
                else:
                    a.pop(0)
                    # izbacuje nulti element liste, točnije string 'mkdir'
                    if(len(a)<2):
                        novi = (os.path.basename(a[0]))
                        # zadnji direktorij u navedenom putu
                        baza = (os.path.dirname(a[0]))
                        # cjeloviti put k direktoriju, ne uključujući zadnji direktorij
                        put = os.path.join(baza, novi)
                        # cjeloviti put k direktoriju + direktorij
                        if (os.path.exists(put)==True):
                        # provjera postoji li već navedeni direktorij
                            vrijeme(unos)
                            salji_cli("Datoteka vec postoji")
                            print("Datoteka vec postoji")
                        elif (os.path.exists(baza)==False):
                        # provjera postoji li upisana adresa, ne uključujući zadnji direktorij
                            vrijeme(unos)
                            salji_cli('Krivo upisana adresa')
                            print('Krivo upisana adresa')
                        else:
                            os.mkdir(put)
                            vrijeme(unos)
                            salji_cli('Direktorij je kreiran.')
                            print('Direktorij je kreiran.')
                    else:
                        vrijeme(unos)
                        salji_cli("Naredba mkdir prima samo jedan argument, unijeli ste previse argumenata ")
                        print("Naredba mkdir prima samo jedan argument, unijeli ste previse argumenata ")
            #kill
            elif (a[0] == 'kill'):
                k = os.getpid()
                # k= vrijednost PID-a trenutnog procesa
                if (len(a) == 1):
                # ako je duljina polja a=1 onda je unesena samo naredba kill
                    vrijeme(unos)
                    salji_cli('Naredba kill prima tocno jedan parametar (naziv signala ili njegov redni broj)')
                    print('Naredba kill prima točno jedan parametar (naziv signala ili njegov redni broj)')
                elif (len(a) == 2):
                # ako je duljina polja a=2 onda je uz naredbu kill uneseno jos nesto
                    """if (a[1] == 'SIGINT' or a[1] == '-INT' or a[1] == '-2'):
                        vrijeme(unos)
                        salji_cli('Izvrsit ce se naredba kill SIGINT')
                        print('Izvrsit ce se naredba kill SIGINT')
                        os.kill(k, 2)"""
                        # ako je uz naredbu kill unesen parametar za signal broj 2, on se izvršava
                    if (a[1] == '-SIGQUIT' or a[1] == '-QUIT' or a[1] == '-3'):
                        signal.signal(signal.SIGQUIT, signal.SIG_IGN)
                        # ako je uz naredbu kill unesen parametar za signal broj 3, on se ignorira
                        vrijeme(unos)
                        salji_cli('Signal broj 3 je ignoriran.')
                        print('Signal broj 3 je ignoriran.')
                    elif (a[1] == '-SIGTERM' or a[1] == '-TERM' or a[1] == '-15'):
                        vrijeme(unos)
                        salji_cli('Pristigao je signal broj 15. Zahvaljujemo na koristenju ovog programa. Program se zavrsava.')
                        print('Pristigao je signal broj 15. Zahvaljujemo na korištenju ovog programa. Program se završava.')
                        sys.exit()
                        # ako je uz naredbu kill unesen parametar za signal broj 15, program završava izvođenje
                    elif (a[1].startswith('-') == False):
                        vrijeme(unos)
                        salji_cli('Naredba kill ne prima argumente')
                        print('Naredba kill ne prima argumente')
                        # ako unesena riječ nakon kill ne počinje s - tj. nije parametar ispisuje se poruka
                    else:
                        vrijeme(unos)
                        salji_cli('Naredba kill prima tocno jedan parametar (za signale broj 2, 3 i 15)')
                        print('Naredba kill prima točno jedan parametar (za signale broj 2, 3 i 15)')
                        # ako unesena riječ nakon kill počinje sa - ,ali nije jedan od parametara za signale broj 2, 3 i 15, ispisuje se poruka
                else:
                    vrijeme(unos)
                    salji_cli('Naredba kill prima tocno jedan parametar (naziv signala ili njegov redni broj) \n- za signale broj 2, 3 i 15, ne prima argumente')
                    print('Naredba kill prima točno jedan parametar (naziv signala ili njegov redni broj) \n- za signale broj 2, 3 i 15, ne prima argumente')
                    # ako je nakon naredbe kill uneseno više parametara ili argumenata ispisuje se poruka

            #ls
            elif (a[0] == 'ls'):
                l = os.listdir(os.getcwd())
                niz = ''
                # l=lista sadrzaja direktorija adrese radnog direktorija
                if (len(a) == 1):
                # ako je duljina polja a=1 onda je unesena samo naredba ls
                    vrijeme(unos)
                    for i in range(len(l)):
                        if (l[i].startswith('.') == False):
                        # ako prvo sadrzaj polja pocinje s . ne ispisati, u suprotnom ispisati polje
                            niz = niz + l[i] + '\n'
                            print(l[i])
                    salji_cli(niz)
                elif (len(a) == 2):
                # ako je duljina polja a=2 onda je uz naredbu ls uneseno jos nesto
                    if (a[1] == '-l'):
                        vrijeme(unos)
                        for i in range(len(l)):
                            if (l[i].startswith('.') == False):
                                niz = niz + ('{}\t{}\t{}\t{}\t{}\t{}\n'.format(os.stat(l[i]).st_mode, os.stat(l[i]).st_nlink,
                                                                os.stat(l[i]).st_uid, os.stat(l[i]).st_gid,
                                                                os.stat(l[i]).st_size, l[i]))
                                print('{}\t{}\t{}\t{}\t{}\t{}'.format(os.stat(l[i]).st_mode, os.stat(l[i]).st_nlink,
                                                                os.stat(l[i]).st_uid, os.stat(l[i]).st_gid,
                                                                os.stat(l[i]).st_size, l[i]))
                        salji_cli(niz)
                        # ako je uz naredbu ls unesen parametar -l i ako sadrzaj liste ne pocinje s . ispisuje redom:
                        # mode, hard links, UID vlasnika, GID vlasnika, veličinu te naziv datoteke odnosno direktorija
                    elif (a[1].startswith('-') == True):
                        vrijeme(unos)
                        salji_cli('Naredba ls ne prima nikakve parametre osim -l')
                        print('Naredba ls ne prima nikakve parametre osim -l')
                        # ako je nakon naredbe ls unesen parametar koji nije -l ispisuje se poruka

                    elif (a[1].startswith('/') == True):
                        # ako je nakon naredbe ls unesena apsolutna adresa vrše se uvjeti dolje
                        if ((os.path.exists(a[1])) == False):
                        # ako adresa ne postoji ispisuje se poruka
                            vrijeme(unos)
                            salji_cli('Ova adresa na vodi do zeljenog direktorija.')
                            print('Ova adresa na vodi do zeljenog direktorija.')
                        else:
                            l = os.listdir(os.chdir(a[1]))
                            vrijeme(unos)
                            for i in range(len(l)):
                                if (l[i].startswith('.') == False):
                                # ako sadrzaj polja pocinje s . ne ispisati, u suprotnom ispisati polje
                                    niz = niz + l[i] + '\n'
                                    print(l[i])
                            salji_cli(niz)
                    elif (a[1].startswith('.') == True):
                        # ako je nakon naredbe ls unos koji počinje s . ispisuje se poruka
                        vrijeme(unos)
                        salji_cli('Naredba ls ne prima relativne adrese.')
                        print('Naredba ls ne prima relativne adrese.')
                    else:
                        vrijeme(unos)
                        salji_cli('Unijeli ste pogrešan argument')
                        print('Unijeli ste pogrešan argument')
                elif (len(a) == 3):
                # uz naredbu ls uneseno je 2 argumenta, 2 parametra ili parametar i argument
                    if (a[1] == '-l'):
                    # nakon naredbe ls unesen je parametar -l
                        if (a[2].startswith('/') == True):
                        # ako je nakon naredbe ls unesena apsolutna adresa vrše se uvjeti dolje
                            if ((os.path.exists(a[2])) == False):
                            # ako adresa ne postoji ispisuje se poruka
                                vrijeme(unos)
                                salji_cli('Ova adresa ne vodi do zeljenog direktorija.')
                                print('Ova adresa ne vodi do zeljenog direktorija.')
                            else:
                                l = os.listdir(os.chdir(a[2]))
                                vrijeme(unos)
                                for i in range(len(l)):
                                    if (l[i].startswith('.') == False):
                                        niz = niz + ('{}\t{}\t{}\t{}\t{}\t{}\n'.format(os.stat(l[i]).st_mode, os.stat(l[i]).st_nlink,
                                                                    os.stat(l[i]).st_uid, os.stat(l[i]).st_gid,
                                                                    os.stat(l[i]).st_size, l[i]))
                                        print('{}\t{}\t{}\t{}\t{}\t{}'.format(os.stat(l[i]).st_mode, os.stat(l[i]).st_nlink,
                                                                    os.stat(l[i]).st_uid, os.stat(l[i]).st_gid,
                                                                    os.stat(l[i]).st_size, l[i]))
                                salji_cli(niz)
                        elif (a[2].startswith('.') == True):
                        # ako je nakon naredbe ls unos koji počinje s . ispisuje se poruka
                            vrijeme(unos)
                            salji_cli('Naredba ls ne prima relativne adrese.')
                            print('Naredba ls ne prima relativne adrese.')
                        else:
                            vrijeme(unos)
                            salji_cli('Unijeli ste pogresan argument')
                            print('Unijeli ste pogrešan argument')
                    else:
                        vrijeme(unos)
                        salji_cli('Unijeli ste pogresan parametar.')
                        print('Unijeli ste pogrešan parametar.')
                        # ako je parametar razlicit od -l ispisuje se poruka
                else:
                    vrijeme(unos)
                    salji_cli("Unijeli ste previse parametara ili argumenta")
                    print("Unijeli ste previse parametara ili argumenta")
                    # ako je duljina a>3 ispisuje se poruka

            #kvadrat
            elif (a[0] == 'kvadrat'):
                a.pop(0)
                # izbacujemo nulti element liste, odnosno string 'kvadriraj'
                if (len(a) == 0):
                # izvodi se ako je lista dužine 0, odnosno ako je naredba bila unesena bez argumenata
                    t1 = threading.Thread(target=podijeli, args=(1, 39999))
                    # dretva 1
                    t2 = threading.Timer(1, podijeli, args=(39999, 69999))
                    # dretva 2 koja se pokreće istekom timera
                    t3 = threading.Thread(target=podijeli, args=(69999, 90000))
                    # dretva 3
                    t4 = threading.Thread(target=podijeli, args=(90000, 95999))
                    # dretva 4

                    t1.start()
                    t2.start()
                    t3.start()
                    t4.start()
                    t1.join()
                    t2.join()
                    t3.join()
                    t4.join()
                    vrijeme(unos)
                    salji_cli("Sve su dretve zavrsile svoje izvodenje!")
                    print("Sve su dretve završile svoje izvođenje!")
                else:
                    vrijeme(unos)
                    salji_cli("Naredba kvadriraj ne prima ni argumente ni parametre!")
                    print("Naredba kvadriraj ne prima ni argumente ni parametre!")

def remoteshd():
    # citanje iz konfiguracijske datoteke
    config = configparser.ConfigParser()
    config.read('/home/martina/labosi_sig/zavrsni/remoteshd.conf')
    config.sections()
    a = config["DEFAULT"]["Port"]
    a=int(a)
    return a



# stavranje privatnog asimetricnog kljuca
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size = 2048,
)
private_key_pem = private_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format = serialization.PrivateFormat.PKCS8,
    encryption_algorithm = serialization.BestAvailableEncryption(b'2134')
)

# stvaranje javnog asimetricnog kljuca
public_key = private_key.public_key()
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM, 
    format=serialization.PublicFormat.PKCS1
)


# zapisivanje asimetricnih kljuceva u datoteke
pr = open("private_key.pem", "wb")
pu = open("public_key.pem", "wb")
pr.write(private_key_pem)
pu.write(public_key_pem)
pr.close()
pu.close()

"""
# citanje iz konfiguracijske datoteke
config = configparser.ConfigParser()
config.read('/home/martina/labosi_sig/zavrsni/remoteshd.conf')
config.sections()
a = config["DEFAULT"]["Port"]
a=int(a)
"""
# u varijeblu port se pohranjuje vrijenost koju se pročita iz konfirguracijske datoteke u funkciji remoteshd
port = remoteshd()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind(('localhost', port))
sock.listen(1)
clisock, addr = sock.accept()

f1 = open("users-passwords.conf", "r")

"""
# posluzitelj prima korisnicko ime i sifru od klijenta
sifra = clisock.recv(1024)
sifra_p = sifra.decode()
"""




# dekriptiranje korinsickog imena i lozinke za provjeru 
ime_sif = clisock.recv(1024)
sifra_p= private_key.decrypt(
    ime_sif,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
).decode()







poruka_t = 'logirani ste '
poruka_f = 'niste logirani '
provjera = 0

for i in f1:
    if (i == sifra_p + '\n'):
        # posluzitelj salje poruku o prijavi
        posalji = poruka_t.encode()
        clisock.send(posalji)
       
        ciphertext = clisock.recv(1024)
        # dekriptiranje simetricnog kljuca za sifriranje privatnim asimetricnim kljucem
        symetric_key_decrypted = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # simetricni kljuc za sifriranje u sessiji
        fkey=Fernet(symetric_key_decrypted)

        tim10()
        provjera = provjera + 1
        break
else:
    if(provjera == 0):
        # posluztelj salje poruku da prijeve nije uspjesna
        posalji = poruka_f.encode()
        clisock.send(posalji)


f1.close()

clisock.close()
sock.close()
