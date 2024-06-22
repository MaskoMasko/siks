import getpass
import crypt

# sluzi za generiranje soli za soljenje lozinka
#print(crypt.mksalt())

while True:
    korisnicko_ime = input('Unesite korisnicko ime: ')
    lozinka = getpass.getpass(prompt = 'Upisi sifru za prijavu: ')
    salt='$6$0lgLWJet.bw0sMIq'

    # soljenje lozinka 
    hash = crypt.crypt(lozinka, salt) 

    # otvaranja i upisivanje u datoteku
    f = open("users-passwords.conf", "a")
    f.write(korisnicko_ime + " " + hash + '\n')

    provjera = input("Zelite li upisati jos korisnika (d/n): ")
    odgovor = provjera.upper()
    if(odgovor != 'D'):
        break
    f.close()






