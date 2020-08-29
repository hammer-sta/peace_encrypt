import random,os,hashlib,clipboard
import cryptography,base58,base91,requests
from cryptography.fernet import Fernet
import base64,time,sys,argparse
import pyAesCrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from colorama import Fore, Back, Style
text = ''
parser = argparse.ArgumentParser()
parser.add_argument('-md5', help='hash md5 encrypt', dest='md5')
parser.add_argument('-sha1', help='hash sha1 encrypt', dest='sha1')
parser.add_argument('-sha224', help='hash sha224 encrypt', dest='sha224')
parser.add_argument('-sha256', help='hash sha256 encrypt', dest='sha256')
parser.add_argument('-sha512', help='hash sha512 encrypt', dest='sha512')
parser.add_argument('-sha3_224', help='hash sha3_224 encrypt', dest='sha3_224')
parser.add_argument('-sha3_256', help='hash sha3_256 encrypt', dest='sha3_256')
parser.add_argument('-sha3_512', help='hash sha3_512 encrypt', dest='sha3_512')
parser.add_argument('-shake128', help='hash shake128 encrypt', dest='shake128')
parser.add_argument('-shake256', help='hash shake256 encrypt', dest='shake256')
parser.add_argument('-blake2b', help='hash blake2b encrypt', dest='blake2b')
parser.add_argument('-sha384', help='hash sha384 encrypt', dest='sha384')
parser.add_argument('-blake2s', help='hash blake2s encrypt', dest='blake2s')
parser.add_argument('-pswdgn', help='Password Generator', dest='pswdgn')
parser.add_argument('-base16', help='base16 encrypt', dest='base16')
parser.add_argument('-base32', help='base32 encrypt', dest='base32')
parser.add_argument('-base58', help='base58 encrypt', dest='base58')
parser.add_argument('-base64', help='base64 encrypt', dest='base64')
parser.add_argument('-base85', help='base85 encrypt', dest='base85')
parser.add_argument('-base91', help='base91 encrypt', dest='base91')
parser.add_argument('-sm', help='Small Password Generator', dest='sm')
parser.add_argument('-big', help='big Password Generator', dest='big')
parser.add_argument('-chr', help='Char ()(*&^%$#@! in Password Generator', dest='chr')
parser.add_argument('-num', help='Number Password Generator', dest='num')
parser.add_argument('-e', help='Encode', dest='e')
parser.add_argument('-d', help='Decode', dest='d')

parser.add_argument('-rng', help='Range For Password Generator', dest='rng' ,type=int)
parser.add_argument('-t', help='text', dest='text')
args = parser.parse_args()
def ppp(g , c , p):
    password = p.encode()
    salt = b'salt_'  
    kdf = PBKDF2HMAC(
		    algorithm=hashes.SHA256(),
		    length=32,
		    salt=salt,
		    iterations=100000,
		    backend=default_backend()
		)
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    if g=='e':
            return f.encrypt(c.encode())
    else:
            return f.decrypt(c.encode())
def bs():
	print(Fore.GREEN+'1 - Base16\n2 - Base32\n3 - Base58\n4 - Base64\n5 - Base85\n6 - Base91')
	mn = input(Fore.WHITE+'\n---------------------------------\nPress Enter The Number =>')
	if mn=='1':
		print(Fore.YELLOW+'1 - Encode\n2 - Decode')
		en = input(Fore.RED+'Press Enter The Number =>')
		text = input(Fore.WHITE+'Press Enter The Text => ')
		if en=='1':
			print(Fore.GREEN+'Encode Done => '+base64.b16encode(text.encode()).decode())
		elif en=='2':
			try :
				print(Fore.GREEN+'Decode Done => '+base64.b16encode(text.decode()).decode())
			except:
				print(Fore.RED+'ERROR :: Decode Is Error')
		else:
			pass

	elif mn=='2':
		print(Fore.YELLOW+'1 - Encode\n2 - Decode')
		en = input(Fore.RED+'Press Enter The Number =>')
		text = input(Fore.WHITE+'Press Enter The Text => ')
		if en=='1':
			print(Fore.GREEN+'Encode Done => '+base64.b32encode(text.encode()).decode())
		elif en=='2':
			try :
				print(Fore.GREEN+'Decode Done => '+base64.b32decode(text.encode()).decode())
			except:
				print(Fore.RED+'ERROR :: Decode Is Error')
		else:
			pass
	elif mn=='6':
		print(Fore.YELLOW+'1 - Encode\n2 - Decode')
		en = input(Fore.RED+'Press Enter The Number =>')
		text = input(Fore.WHITE+'Press Enter The Text => ')
		if en=='1':
			print(Fore.GREEN+'Encode Done => '+base91.encode(text.encode()))
		elif en=='2':
			try :
				print(Fore.GREEN+'Decode Done => '+base91.decode(text).decode())
			except:
				print(Fore.RED+'ERROR :: Decode Is Error')
		else:
			pass
	elif mn=='4':
		print(Fore.YELLOW+'1 - Encode\n2 - Decode')
		en = input(Fore.RED+'Press Enter The Number =>')
		text = input(Fore.WHITE+'Press Enter The Text => ')
		if en=='1':
			print(Fore.GREEN+'Encode Done => '+base64.b64encode(text.encode()).decode())
		elif en=='2':
			try :
				print(Fore.GREEN+'Decode Done => '+base64.b64decode(text.encode()).decode())
			except:
				print(Fore.RED+'ERROR :: Decode Is Error')
		else:
			pass

	elif mn=='5':
		print(Fore.YELLOW+'1 - Encode\n2 - Decode')
		en = input(Fore.RED+'Press Enter The Number =>')
		text = input(Fore.WHITE+'Press Enter The Text => ')
		if en=='1':
			print(Fore.GREEN+'Encode Done => '+base64.b85encode(text.encode()).decode())
		elif en=='2':
			try :
				print(Fore.GREEN+'Decode Done => '+base64.b85decode(text.encode()).decode())
			except:
				print(Fore.RED+'ERROR :: Decode Is Error')
		else:
			pass
	elif mn=='3':
		print(Fore.YELLOW+'1 - Encode\n2 - Decode')
		en = input(Fore.RED+'Press Enter The Number =>')
		text = input(Fore.WHITE+'Press Enter The Text => ')
		if en=='1':
			print(Fore.GREEN+'Encode Done => '+base58.b58encode(text.encode()).decode())
		elif en=='2':
			try :
				print(Fore.GREEN+'Decode Done => '+base58.b58decode(text.encode()).decode())
			except:
				print(Fore.RED+'ERROR :: Decode Is Error')
		else:
			pass

	input('Press Any Key...')
	menu()
def PBKDF2HMAC1():
        os.system('clear')        
        print(Fore.WHITE+"1 - Encode\n2 - Decode")
        mnu = input("Press Enter The Number => ")
        password = input("Press Enter The Password => ")
        co = input("Copy => ")
        fite = input("Text Or File (1 , 2) => ")
        if fite == '2':
                address = input("Press Enter The Address File => ")
                address2 = input("Press Enter The Address Save File => ")
                try:
                        with open(address , 'rb') as f:
                                ttt = f.read()
                        with open(address2 , 'wb') as f:
                                if mnu=='1':
                                        f.write(ppp('e' , ttt.decode('utf-8') , password))
                                else:
                                        try :
                                            f.write(ppp('d' , ttt.decode('utf-8') , password))
                                        except cryptography.fernet.InvalidToken:
                                            input("Password In Corrent...")
                                            PBKDF2HMAC1()
                        input("Done!")
                        PBKDF2HMAC1()
                except FileNotFoundError:
                        input("file Not Found!...")
                        PBKDF2HMAC1()
        if fite=="1":
            text  = input("Press Enter The Cipher Or Text => ")
            if mnu=="1":
                text = ppp('e' , text , password).decode()
                if co == "y" or "yes" or "Y":
                    try:
                        clipboard.copy(text)
                        print("Copy IS DONE")
                    except:
                        print("[-] Error in Copy ")
                    input(f"[+] => {text}")
            if mnu=='2':
                text = ppp('d' , text , password).decode()
                if co == "n" or "no" or "N":
                    try:
                        clipboard.copy(text)
                        print("Copy IS DONE")
                    except:
                        print("[-] Error in Copy ")
                    input(f"[+] => {text}")                
        menu()                    
def enfile():
	print(Fore.RED+'Encrypting files is the first step to security')
	print('-'*60)
	print('1 - Encode\n2 - Decode')
	mn = input("----------------\nPress Enter The Number => ")
	path = input('Press Enter The Path File => ')
	path2 = input('Press Enter The Path File Save => ')
	password = input("Press Enter The Password =>")
	if mn=='1':
		try :
			pyAesCrypt.encryptFile(path , path2 , password , 64*1024)
			print(Fore.GREEN+'Save And Encode Done!')
		except:
			print(Fore.RED+"ERROR :: ERROR IN Save And Encode")
	elif mn=='2':
		try :
			pyAesCrypt.decryptFile(path , path2 , password , 64*1024)
			print(Fore.GREEN+'Save And Encode Done!')
		except:
			print(Fore.RED+"ERROR :: ERROR IN Save And Encode")
	else:
		menu()
	input("Press Any Key...")
	menu()
def md5(ttt):
	m = hashlib.md5()
	m.update(ttt.encode())
	return m.hexdigest()
def sha1(ttt):
	m = hashlib.sha1()
	m.update(ttt.encode())
	return m.hexdigest()

def sha224(ttt):
	m = hashlib.sha224()
	m.update(ttt.encode())
	return m.hexdigest()


def sha256(ttt):
	m = hashlib.sha256()
	m.update(ttt.encode())
	return m.hexdigest()

def sha384(ttt):
	m = hashlib.sha384()
	m.update(ttt.encode())
	return m.hexdigest()

def sha512(ttt):
	m = hashlib.sha512()
	m.update(ttt.encode())
	return m.hexdigest()

def sha3_224(ttt):
	m = hashlib.sha3_224()
	m.update(ttt.encode())
	return m.hexdigest()
def sha3_256(ttt):
	m = hashlib.sha3_256()
	m.update(ttt.encode())
	return m.hexdigest()
def sha3_512(ttt):
	m = hashlib.sha3_512()
	m.update(ttt.encode())
	return m.hexdigest()
def shake128(ttt):
	m = hashlib.shake_128()
	m.update(ttt.encode())
	return m.hexdigest()
def shake256(ttt):
	m = hashlib.shake_256()
	m.update(ttt.encode())
	return m.hexdigest()
def blake2b(ttt):
	m = hashlib.blake2b()
	m.update(ttt.encode())
	return m.hexdigest()
def blake2s(ttt):
	m = hashlib.blake2s()
	m.update(ttt.encode())
	return m.hexdigest()
def hash1():
	global text
	print(Fore.RED+'1 - Encrypt\n2 - Crack')
	nn = input(Fore.GREEN+'-------------------\nPress Enter The Number => ')	
	if nn=='1':
		mn = input('''
1-md5
2-sha1
3-sha224
4-sha256
5-sha512
6-sha3_224
7-sha3_256
8-sha3_512
9-shake_128
10-shake_256
11-blake2b 
12-blake2s
13-sha384
__________________________
Press Enter The Hash => ''')
		
		if int(mn) > 14:
			os.system('clear')
			print('\033[91mNot Found Hashes')
			color()
			hash1()
		type1 = input('File Or Text (1 , 2) => ')
		if type1=='1':
			path = input('Press Enter Path File => ')
			try :
				with open(path , 'rb') as f:
					text = f.read().decode()
			except FileNotFoundError:
				print(Fore.RED , 'Error :: File Not Found')
				input('Press Any Key...')
				menu()
		elif type1=='2':
			text = input('Press Enter The text =>')	
		else:
			menu()
		
		if mn=='1':
			print('Hash Md5 Is => ' + md5(text))
		elif mn=='2':
			print('Hash sha1 Is => ' + sha1(text))
		elif mn=='3':
			print('Hash sha224 Is => ' + sha224(text))
		elif mn=='4':
			print('Hash sha256 Is => ' + sha256(text))
		elif mn=='5':
			print('Hash sha512 Is => ' + sha512(text))
		elif mn=='6':
			print('Hash sha3_224 Is => ' + sha3_224(text))
		elif mn=='7':
			print('Hash sha3_256 Is => ' + sha3_256(text))
		elif mn=='8':
			print('Hash sha3_512 Is => ' + sha3_512(text))
		elif mn=='9':
			print('Hash shake_128 Is => ' + shake_128(text))
		elif mn=='10':
			print('Hash shake_256 Is => ' + shake_256(text))
		elif mn=='11':
			print('Hash blake2b Is => ' + blake2b(text))
		elif mn=='12':
			print('Hash blake2s Is => ' +blake2s(text))
		elif mn=='13':
			print('Hash sha384 Is => ' + sha384(text))
	elif nn=='2':
		text2 = input(Fore.WHITE+'Press Enter The Cipher =>')
		a = ['md5' , 'sha256','sha384','sha512']
		for i in a:
			r = requests.get('https://md5decrypt.net/Api/api.php?hash=%s&hash_type=%s&email=deanna_abshire@proxymail.eu&code=1152464b80a61728' % (text2, i)).text
			if r=='CODE ERREUR : 005':
				print(Fore.WHITE+Back.RED+i+'::Not Found!')
			else:
				for i34 in r.split('\n'):
					print(Back.GREEN+Fore.BLACK+i+'::'+i34)
					break
			
	input(Back.BLACK+Fore.WHITE+'Press Enter...')
	menu()
def passwordgen():
	abc = ''
	print(Fore.LIGHTRED_EX)
	m = input('Char (!@#$%^&*()_+) in Password (Y or N) => ')
	n = input('Number in Password (Y or N) => ')
	h = input('Big in Password (Y or N) => ')
	s = input('Small in Password (Y or N) => ')
	S = input('Save File (Y or N) => ')
	C = input('Copy Password (Y or N) => ')
	gg = input('Type a name for the password (if No Press Enter) => ')
	r = int(input('Press Enter Range password => '))
	gg = gg.split(' ')
	c = ''
	for i in gg:
		c+= i		
	if m=='y' :
		abc += '~!@#$%^&*()_+'
	elif m=='y' :
		abc += '~!@#$%^&*()_+'
	if n=='y':
		abc+='1234567890'
	elif n=='Y':
		abc+='1234567890'
	if s=='y':
		abc+='abcdefghijklmnopqrstuvwxyz'
	elif s=='Y':
		abc+='abcdefghijklmnopqrstuvwxyz'
	if h=='y':
		abc+='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	elif h=='Y':
		abc+='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	password = ''
	a = random.randint(0 , int(r))
	for i in range(0 , a):
		password += random.choice(abc)
	password += c
	r = r-a
	for i in range(0 , r):
		password+= random.choice(abc)
	if S=='y':
		try :
			v = str(random.randint(0 , 10000))
			with open(v+'.txt' , 'a') as f:
				f.write(password)
			print(f'Save Password in {v}')
		except:
			print('\033[91mError Save Password...')			
	input('Password Is => ' + password)
	menu()	
def slowprint(s):
    for c in s + '\n':
        sys.stdout.write(c)
        sys.stdout.flush()
        time.sleep(4. / 100)
def menu():
	print(Fore.BLACK,Back.BLACK)
	os.system('clear')
	print(Fore.RED , '''
 ███████████  ██████████   █████████     █████████  ██████████
░░███░░░░░███░░███░░░░░█  ███░░░░░███   ███░░░░░███░░███░░░░░█
 ░███    ░███ ░███  █ ░  ░███    ░███  ███     ░░░  ░███  █ ░ 
 ░██████████  ░██████    ░███████████ ░███          ░██████   
 ░███░░░░░░   ░███░░█    ░███░░░░░███ ░███          ░███░░█   
 ░███         ░███ ░   █ ░███    ░███ ░░███     ███ ░███ ░   █
 █████        ██████████ █████   █████ ░░█████████  ██████████
░░░░░        ░░░░░░░░░░ ░░░░░   ░░░░░   ░░░░░░░░░  ░░░░░░░░░░ 
A tool for encryption and decryption
''')
	print(Fore.GREEN+'-'*60)
	print('1 - Hash\n2 - Password Generator\n3 - PBKDF2_HMAC\n4 - Bases\n5 - Encrypt File With AES')
	mnu = input('Press Enter The Number => ')
	if mnu=='1':
		os.system('clear')
		hash1()
	elif mnu=='2':
		os.system('clear')	
		passwordgen()
	elif mnu=='4':
		os.system('clear')
		bs()
	elif mnu=='5':
		os.system('clear')
		enfile()
	elif mnu=='3':
		os.system('clear')
		PBKDF2HMAC1()
	elif mnu=='q':
		os._exit(0)
	else:
		menu()
if args.md5:
	print(md5(args.text))
elif args.sha1:
	print(sha1(args.text))
elif args.sha224:
	print(sha224(args.text))
elif args.sha256:
	print(sha256(args.text))
elif args.sha512:
	print(sha512(args.text))
elif args.sha3_224:
	print(sha3_224(args.text))
elif args.sha384:
	print(sha384(args.text))
elif args.sha3_256:
	print(sha3_256(args.text))
elif args.sha3_512:
	print(sha3_512(args.text))
elif args.shake128:
	print(shake128(args.text))
elif args.shake256:
	print(shake256(args.text))
elif args.blake2b:
	print(blake2b(args.text))
elif args.blake2s:
	print(blake2s(args.text))
elif args.base16:                
        if args.e:
                print(base64.b16encode(args.text.encode()).decode())
        elif args.d:
                print(base64.b16decode(args.text.encode()).decode())
elif args.base32:        
        if args.e:
                print(base64.b32encode(args.text.encode()).decode())
        elif args.d:
                print(base64.b32decode(args.text.encode()).decode())
        
elif args.base58:
	print(base58.b58encode(args.text.encode()).decode())
elif args.base64:
	print(base64.b64encode(args.text.encode()).decode())
elif args.base85:
	print(base64.b85encode(args.text.encode()).decode())
elif args.base91:
	print(base91.encode(args.text.encode()))
elif args.pswdgn:
	abc = ''
	if args.chr:
		abc += '~!@#$%^&*()_+'
	if args.num:
		abc+='1234567890'
	if args.sm:
		abc+='abcdefghijklmnopqrstuvwxyz'
	if args.big:
		abc+='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	password = ''
	r = int(args.rng)
	a = random.randint(0 , r)
	for i in range(0 , a):
		password += random.choice(abc)
	if args.text:
		password += args.text
	r = r-a
	for i in range(0 , r):
		password+= random.choice(abc)
	print(password)
else:
	menu()