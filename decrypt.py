import zono.zonocrypt as zonocrypt
import sys
import os
import clipboard
import zipfile
import subprocess
import time
import zono.colorlogger as cl
import platform 

windows = platform.system() == 'Windows'
def hide_dir(Dir):
    if windows:
        subprocess.check_call(['attrib', '+H', Dir])
    else:
        subprocess.check_call(['chflags','hidden',Dir])

def unzip(path):
    with zipfile.ZipFile(path, 'r') as ZIP:
        ZIP.extractall()


__all__ = ['-of', '-i', '-replace', '-pass', '-info', '-help', '?', '-load']

__help__ = """df decrypts files or folders encrypted with ef file/folder encrypter
-of        changes the output file
-i         ignores all warnings
-replace   replaces the input file
-load      decrypts the file than allows you to veiw the encrypted file without saving it
-pass      provide a string password which is later turned in to a secure b64 encoded key
-info      displays extra information about the decrypted file
-help/?    displays this message"""


args = sys.argv
args.pop(0)

INFO = False
if '-info' in args:
    start_time = time.time()
    INFO = True

if '?' in args or '-help' in args:
    print(__help__)
    sys.exit()
try:
    input_file = args[0]
except:
    cl.error('First Argument Must be the input file')
    sys.exit()
try:
    key = args[1]
except:
    cl.error('second argument must be the encryption key')
    sys.exit()




key = bytes(key, 'utf-8')
# key = b'mg8ZusULc_AIIkZswmh6UvZ-G5UnLuvklYK06TAqpj4='

warn = True
if '-i' in args:
    warn = False


out_file = False
if '-of' in args:
    try:
        index = args.index('-of')
        output_file = args[index + 1]
        out_file = True
    except:
        cl.error('Output file should be provided after -of')
        sys.exit()

path = os.getcwd()


for i in args:
    if i not in __all__:
        if not i[0] == '-':
            continue
        cl.error('Invalid argument ' + str(i) + ' type -help or ? for help')
        sys.exit()

if not os.path.exists(input_file):
    cl.error(f'file {input_file} does not exist')
    sys.exit()


try:
    filesize = round(os.stat(input_file).st_size / (1024 * 1024), 2)
    filesize_form = f'{filesize}mb'

    crypt = zonocrypt.zonocrypt()
    if input_file == '/' or input_file == '\\':
        cl.error('Invalid file name')
        sys.exit()


    with open(input_file, 'r') as file:
        f = file.read()

    if '-pass' in args:
        try:
            index = args.index('-pass')
            password = args[index + 1]

            key = crypt.str_to_valid_key(password)

        except:
            cl.error('Output file should be provided after -of')
            sys.exit()

    index = f.index('[')

    file_type_list = []

    for i in range(index, len(f)):
        file_type_list.append(f[i])

    file_name_ = ''.join(file_type_list)

    to_remove = len(f) - index
    hash_str = f[:-to_remove]

    # sys.exit()

    file_hash = bytes(hash_str, 'utf-8')
    file_name_enc = file_name_.replace('[', '').replace(
        ']', '').replace("b'", '').replace("'", "")

    file_name_enc_bytes = bytes(file_name_enc, 'utf-8')

    if '!' in file_name_enc:
        if '-replace' in args:
            if warn:
                while True:
                    q = input(
                        f'-replace deletes the original file are you sure you would like to proceed y/n add -i to ignore warnings:').lower()

                    if q == 'y':
                        break
                    elif q == 'n':
                        sys.exit()

            os.remove(input_file)

        file_name_enc = file_name_enc.replace('!', '')

        file_name_enc_bytes = bytes(file_name_enc, 'utf-8')
        try:
            file_name__ = crypt.decrypt_raw(
                file_name_enc_bytes, key).decode('utf-8')
        except zonocrypt.symmetric_encryption.crypt.IncorrectDecryptionKey:
            cl.error('Incorrect decryption Key')
            sys.exit()

        file = os.path.basename(file_name__)

        FILE = file

        file_data = os.path.splitext(file)

        file_name = file_data[0]
        file_type = file_data[1]

        file_bytes_dec = crypt.decrypt_raw(file_hash, key)

        zip_name = f'{file_name}_dec_zip.zip'

        if os.path.exists(zip_name):
            if warn:
                while True:
                    q = input(
                        f'file {zip_name} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()
                    if q == 'y':
                        break
                    elif q == 'n':
                        sys.exit()

        with open(zip_name, 'wb') as file:
            file.write(file_bytes_dec)
        hide_dir(zip_name)

        if os.path.exists(file_name):
            if warn:
                while True:
                    q = input(
                        f'file {file_name} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()
                    if q == 'y':
                        break
                    elif q == 'n':
                        sys.exit()

        unzip(zip_name)

        os.remove(zip_name)

        if INFO:
            filesize_out = round(os.stat(FILE).st_size / (1024 * 1024), 2)
            filesize_out_form = f'{filesize_out}mb'
            diffrence = round(filesize_out-filesize, 2)

            print(
                f'Folder successfully decrypted\nInput file size: {filesize_form}\nOutput file size: {filesize_out_form}\nSize diffrence: {diffrence}mb\nTime taken: {round(time.time()-start_time,2)}s')

        else:
            print('Folder successfully decrypted')

        sys.exit()

    if '#' in file_name_enc:
        if '-replace' in args:
            if warn:
                while True:
                    q = input(
                        f'-replace deletes the original file are you sure you would like to proceed y/n add -i to ignore warnings:').lower()

                    if q == 'y':
                        break
                    elif q == 'n':
                        sys.exit()

            os.remove(input_file)

        file_name_enc = file_name_enc.replace('!', '')

        file_name_enc_bytes = bytes(file_name_enc, 'utf-8')
        try:
            file_name__ = crypt.decrypt_raw(
                file_name_enc_bytes, key).decode('utf-8')
        except zonocrypt.symmetric_encryption.crypt.IncorrectDecryptionKey:
            cl.error('Incorrect decryption Key')
            sys.exit()

        file = os.path.basename(file_name__)

        FILE = file

        file_data = os.path.splitext(file)

        file_name = file_data[0]
        file_type = file_data[1]

        file_bytes_dec = crypt.decrypt_raw(file_hash, key)

        zip_name = f'{file_name}_dec_zip.zip'

        if os.path.exists(zip_name):
            if warn:
                while True:
                    q = input(
                        f'file {zip_name} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()
                    if q == 'y':
                        break
                    elif q == 'n':
                        sys.exit()

        with open(zip_name, 'wb') as file:
            file.write(file_bytes_dec)
        hide_dir(zip_name)

        if os.path.exists(FILE):
            if warn:
                while True:
                    q = input(
                        f'file {FILE} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()
                    if q == 'y':
                        break
                    elif q == 'n':
                        sys.exit()

        unzip(zip_name)

        os.remove(zip_name)

        if INFO:
            filesize_out = round(os.stat(FILE).st_size / (1024 * 1024), 2)
            filesize_out_form = f'{filesize_out}mb'
            diffrence = round(filesize_out-filesize, 2)

            print(
                f'Folder successfully decrypted\nInput file size: {filesize_form}\nOutput file size: {filesize_out_form}\nSize diffrence: {diffrence}mb\nTime taken: {round(time.time()-start_time,2)}s')

        else:
            print('Folder successfully decrypted')

        sys.exit()

    try:
        file_name__ = crypt.decrypt_raw(
            file_name_enc_bytes, key).decode('utf-8')
    except zonocrypt.symmetric_encryption.crypt.IncorrectDecryptionKey:
        cl.error('Incorrect decryption Key')
        sys.exit()

    file = os.path.basename(file_name__)

    file_data = os.path.splitext(file)

    file_name = file_data[0]
    file_type = file_data[1]

    file_bytes_dec = crypt.decrypt_raw(file_hash, key)

    if '-replace' in args:
        if warn:
            while True:
                q = input(
                    f'-replace deletes the original file are you sure you would like to proceed y/n add -i to ignore warnings:').lower()

                if q == 'y':
                    break
                elif q == 'n':
                    sys.exit()

        os.remove(input_file)

    if not out_file:
        file_ = f'{file_name}_dec{file_type}'
        if os.path.exists(file_):
            if warn:
                while True:
                    q = input(
                        f'file {file_} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()
                    if q == 'y':
                        break
                    elif q == 'n':
                        sys.exit()

        with open(file_, 'wb') as file:
            file.write(file_bytes_dec)

    else:
        file_ = f'{file_name}_dec.{file_type}'
        if os.path.exists(file_):
            if warn:
                while True:
                    q = input(
                        f'file {file_} already exists in {path} would you like to overwrite it? y/n add -i to ignore warnings:').lower()
                    if q == 'y':
                        break
                    elif q == 'n':
                        sys.exit()
        with open(output_file, 'wb') as file:
            file.write(file_bytes_dec)

    if INFO:
        filesize_out = round(os.stat(file_).st_size / (1024 * 1024), 2)
        filesize_out_form = f'{filesize_out}mb'
        diffrence = round(filesize_out-filesize, 2)

        print(
            f'File successfully decrypted\nInput file size: {filesize_form}\nOutput file size: {filesize_out_form}\nSize diffrence: {diffrence}mb\nTime taken: {round(time.time()-start_time,2)}s')

    else:
        print('File successfully decrypted')

    if INFO <= 1:
        pass

    if '-load' in args:
        import webbrowser
        import time
        webbrowser.open(file_)
        time.sleep(10)
        os.remove(file_)

except KeyboardInterrupt:
    cl.error('Operation cancelled by user')
