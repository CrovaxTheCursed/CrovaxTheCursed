#Decode config data using RC4 algo 
#@author Crovax
#@category Strings
#@keybinding
#@menupath
#@toolbar

import hashlib 
import binascii

def rc4_decrypt(key, data):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = 0
    y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    return ''.join(out)



def get_encrypted_bytes():   
    get_addr = currentAddress
    get_bytes = list(getBytes(get_addr, 2000))
    converted_bytes = ''
    cByte = ''
    for byte in get_bytes:
        if byte < 0:
            cByte = (0xff - abs(byte) + 1)
        else:
            cByte = byte
        converted_bytes += chr(cByte)
        
    return converted_bytes

key_bytes = '\xb3\x03\x18\xaa\x0a\xd2\x77\xde'
print 'key length', len(key_bytes)
get_hash = hashlib.sha1()
get_hash.update(key_bytes)
key_hash = get_hash.digest()[:5]


print 'Current Address:', currentAddress 
print 'Key Hash:',binascii.hexlify(key_hash)

get_data = get_encrypted_bytes()

config =  rc4_decrypt(key_hash, get_data)
build_id = config.split('\x00')[0]
print  'Build_id:', build_id 


for string in config.split('\x00')[1:]:
    if string != '':
        c2 = string
        break
c2_List = c2.split('|')

for c2 in c2_List:
    if c2 != '':
        print 'c2:', c2
    
