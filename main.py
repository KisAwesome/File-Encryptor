import argparse
import shutil
import sys
import zono.zonocrypt
from english_words import english_words_set
import random
import os
import zipfile
import subprocess
import zono.workers
import zono.colorlogger
import time


windows = sys.platform == "win32"


def _divide_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i : i + n]


def chunks(l, n):
    return list(_divide_chunks(l, n))


def log(message, func=zono.colorlogger.log, *args, **kwargs):
    global VERBOSE
    if VERBOSE:
        func(message, *args, **kwargs)


def hide_dir(Dir):
    if windows:
        subprocess.check_call(["attrib", "+H", Dir])
    else:
        subprocess.check_call(["chflags", "hidden", Dir])


def zip_dir(path, zip_path):
    zf = zipfile.ZipFile(f"{zip_path}.zip", "w", zipfile.ZIP_DEFLATED)

    for root, dirs, files in os.walk(path):
        for file_name in files:
            zf.write(os.path.join(root, file_name))


def write_zip(path, zip_path):
    zf = zipfile.ZipFile(f"{zip_path}", "w", zipfile.ZIP_DEFLATED)
    zf.write(path)
    zf.close()


def unzip(path):
    with zipfile.ZipFile(path, "r") as ZIP:
        ZIP.extractall()


def get_random_word():
    return random.choice(english_words_set)


def get_random_string():
    _type = random.randint(1, 5)
    if _type == 1:
        return f"{get_random_word()}{random.randint(0,99)}"
    elif _type == 2:
        return f"{get_random_word()}_{random.randint(0,99)}"
    elif _type == 3:
        return f"{get_random_word()}_{get_random_word()}_{random.randint(0,99)}"
    elif _type == 4:
        return f"{get_random_word()}-{get_random_word()}-{random.randint(0,99)}"
    elif _type == 5:
        return f"{get_random_word()}-{get_random_word()}"


def parse_key(opts):
    global HASHED_KEY, STRING_KEY
    if opts.random_key:
        STRING_KEY = get_random_string()
        HASHED_KEY = crypt.hashing_function(STRING_KEY, salt=b"")

    else:
        STRING_KEY = opts.key
        if opts.hash:
            HASHED_KEY = crypt.hashing_function(STRING_KEY, salt=b"")
            return

        if crypt.check_valid_key(STRING_KEY.encode("utf-8")):
            HASHED_KEY = STRING_KEY
        else:
            HASHED_KEY = crypt.hashing_function(STRING_KEY, salt=b"")


def _encrypt(fbytes, key):
    return crypt.encrypt_bytes(fbytes, key)


def encrypt_folder(opts):
    opts.output_file = opts.output_file or opts.file + ".encrypted"
    start_time = time.time()
    file = "temps.encrypted/file_zip"
    os.makedirs("temps.encrypted")
    zip_dir(opts.file, file)
    log("Zipped folder")

    with open(file + ".zip", "rb") as f:
        file_bytes = f.read()

    log("Loaded file")

    split_file_bytes = chunks(file_bytes, opts.chunk_size)
    log("Split folder into chunks")
    log("Starting threads")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )

    encrypted_chunks = worker.run(split_file_bytes, _encrypt, HASHED_KEY)
    log("Encrypted chunks")
    enc_file_byte = b"&$&".join(encrypted_chunks)

    with open(opts.output_file, "wb") as f:
        f.write(enc_file_byte)

    enc_input_file = crypt.encrypt(opts.file + "$#FOLDER#$", HASHED_KEY)

    with open(opts.output_file, "a") as f:
        f.write(f"[{enc_input_file}]")

    zono.colorlogger.major_log("File successfully encrypted")
    print(f"String key: {STRING_KEY}\nHashed key: {HASHED_KEY.decode('utf-8')}")
    log(f"time taken: {time.time()-start_time}s", print)

    shutil.rmtree("temps.encrypted")
    if opts.replace:
        shutil.rmtree(opts.file)


def encrypt_file(opts):
    input_file = os.path.basename(opts.file)
    input_file_enc = input_file
    opts.output_file = opts.output_file or input_file + ".encrypted"
    start_time = time.time()
    if opts.archive:
        file = "temps.encrypted/file_zip.zip"
        os.makedirs("temps.encrypted")
        write_zip(opts.file, file)
        log("Zipped file")
        opts.file = file
        input_file_enc += "$#ARCHIVED#$"

    with open(opts.file, "rb") as file:
        file_bytes = file.read()

    log("Loaded file")

    split_file_bytes = chunks(file_bytes, opts.chunk_size)
    log("Split file into chunks")
    log("Starting threads")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )

    encrypted_chunks = worker.run(split_file_bytes, _encrypt, HASHED_KEY)
    log("Encrypted chunks")
    enc_file_byte = b"&$&".join(encrypted_chunks)

    with open(opts.output_file, "wb") as f:
        f.write(enc_file_byte)

    enc_input_file = crypt.encrypt(input_file_enc, HASHED_KEY)

    with open(opts.output_file, "a") as f:
        f.write(f"[{enc_input_file}]")

    zono.colorlogger.major_log("File successfully encrypted")
    print(f"String key: {STRING_KEY}\nHashed key: {HASHED_KEY.decode('utf-8')}")
    log(f"time taken: {time.time()-start_time}s", print)
    if opts.archive:
        shutil.rmtree("temps.encrypted")
    if opts.replace:
        os.remove(opts.input_file)


STRING_KEY = None
HASHED_KEY = None

sys.argv.pop(0)

if "--hashing-function" in sys.argv:
    sys.argv.insert(0, __file__)

crypt = zono.zonocrypt.zonocrypt()


pa = argparse.ArgumentParser(prog="File Encrypter")


pa.add_argument("file", help="The file that should be encrypted")

key_gen_group = pa.add_mutually_exclusive_group()

key_gen_group.add_argument("-key", help="The key that is used to encrypt the file")


pa.add_argument(
    "--hash",
    action="store_true",
    help="Hash the key regardless of whether it is already valid",
)


key_gen_group.add_argument(
    "-rk", "--random-key", action="store_true", help="Generates a random random key"
)

pa.add_argument(
    "-archive", action="store_true", help="Compresses the input file before encryption"
)
pa.add_argument(
    "-replace", action="store_true", help="Replace existing file with encrypted version"
)

pa.add_argument(
    "-i", "--ignorewarnings", action="store_true", help="Ignores all warnings"
)

pa.add_argument("-of", "--output-file", help="Manually set the output file")


pa.add_argument(
    "--hashing-function",
    help="Runs the inputed string through the hashing function",
    default=False,
)


pa.add_argument(
    "--max-threads",
    help="Sets the maximum number of threads to use for encryption",
    default=32,
    type=int,
)

pa.add_argument(
    "--chunk-size", help="Sets the chunk size for encryption", default=32768, type=int
)


pa.add_argument("-v", "--verbose", action="store_true", help="Prints extra information")

opts = pa.parse_args(sys.argv)


if opts.hashing_function:
    hashed = crypt.hashing_function(opts.hashing_function, salt=b"").decode("utf-8")
    print(f"The hash for {opts.hashing_function} is {hashed}")
    sys.exit()


if not os.path.exists(opts.file):
    pa.error("Input file does not exist")
if not any([opts.random_key, opts.key]):
    print("No key provided a random key will be used")
    opts.random_key = True


VERBOSE = opts.verbose
parse_key(opts)


if os.path.exists("temps.encrypted"):
    shutil.rmtree("temps.encrypted")
if os.path.isdir(opts.file):
    encrypt_folder(opts)

else:
    encrypt_file(opts)
