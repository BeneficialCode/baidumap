import hashlib
import base64
import os
import sqlite3
from Crypto.Cipher import AES
import hmac

# php decrypt
lockstream = "st=lDEFABCNOPyzghi_jQRST-UwxkVWXYZabcdef+IJK6/7nopqr89LMmGH012345uv"

def decrypt(txt_stream,public_key):
    lock_len = len(lockstream)
    txt_len = len(txt_stream)
    random_lock = txt_stream[txt_len-1]
    lock_count = lockstream.index(random_lock)
    password = hashlib.md5((public_key+random_lock).encode()).hexdigest()

    txt_stream = txt_stream[:-1]
    tmp_stream = ''
    k = 0
    for i in range(len(txt_stream)):
        k = k if k < len(password) else 0
        j = lockstream.index(txt_stream[i])-lock_count-ord(password[k])
        while j < 0:
            j += lock_len
        tmp_stream += lockstream[j]
        k += 1
    try:
        # base64 decode and gbk decode
        text = base64.b64decode(tmp_stream).decode('gbk')
    except Exception as e:
        print("Error: ",e)
        return None
    return text

SQLITE_FILE_HEADER = b"SQLite format 3\x00"

KEY_SIZE = 32
DEFAULT_PAGESIZE = 4096
DEFAULT_ITER = 64000

def decrypt_db(key:str,db_path,out_path):
    if not os.path.exists(db_path) or not os.path.isfile(db_path):
        raise Exception("db_path must be a file")
    with open(db_path,"rb") as file:
        blist = file.read()

    salt = blist[:16]
    byteKey = hashlib.pbkdf2_hmac('sha1',key.encode(),salt,DEFAULT_ITER,dklen=KEY_SIZE)
    # 这里已经把盐值去掉
    first = blist[16:DEFAULT_PAGESIZE]
    if len(salt) != 16:
        raise Exception("salt must be 16 bytes")
    
    mac_salt = bytes([(salt[i] ^ 58) for i in range(16)])
    mac_key = hashlib.pbkdf2_hmac("sha1", byteKey, mac_salt, 2, KEY_SIZE)
    hash_mac = hmac.new(mac_key, first[:-32], hashlib.sha1)
    hash_mac.update(b'\x01\x00\x00\x00')

    if hash_mac.digest() != first[-32:-12]:
        return False, f"[-] Key Error! (key:'{key}'; db_path:'{db_path}'; out_path:'{out_path}' )"

    block_sz = 16

    reserve_sz = 0
    # iv size
    iv_sz = 16
    # hmac size
    hmac_sz = 20

    reserve_sz = iv_sz
    reserve_sz += hmac_sz
    if reserve_sz % block_sz != 0:
        reserve_sz = ((reserve_sz // block_sz) + 1) * block_sz
    print("reserve_sz:",reserve_sz)

    salt_size = 16

    newblist = [blist[i:i + DEFAULT_PAGESIZE] for i in range(DEFAULT_PAGESIZE, len(blist), DEFAULT_PAGESIZE)]

    with open(out_path,"wb") as deFile:
        # 第一页
        deFile.write(SQLITE_FILE_HEADER)
        pos1 = reserve_sz
        pos2 = pos1 - iv_sz
        iv = first[-pos1:-pos2]
        t = AES.new(byteKey, AES.MODE_CBC, iv)
        decrypted = t.decrypt(first[:-pos1])
        deFile.write(decrypted)
        deFile.write(first[-pos1:])

        # 后续页
        for i in newblist:
            pos = reserve_sz - iv_sz
            iv = i[-reserve_sz:-pos]
            t = AES.new(byteKey, AES.MODE_CBC, iv)
            decrypted = t.decrypt(i[:-reserve_sz])
            deFile.write(decrypted)
            deFile.write(i[-reserve_sz:])

    try:
        conn = sqlite3.connect(out_path)
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table';")
        c.close()
        conn.close()
    except Exception as e:
        print("Error: ",e)
        return False
    

def main():
    plain = decrypt("=JF-J-WKsGQTAWHnBPsO/", "fd0f892c9c")
    print(plain)

    decrypt_db("H+^rh$cnM9Szo","new_baidumapfav.db","new_baidumapfav.decrypted.db")

if __name__ == "__main__":
    main()