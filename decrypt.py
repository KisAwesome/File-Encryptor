import argparse
import shutil
import sys
import zono.zonocrypt
import os
import zipfile
import zono.workers
import zono.colorlogger
import time

crypt = zono.zonocrypt.zonocrypt()

HASHED_KEY = None


def _divide_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i : i + n]


def chunks(l, n):
    return list(_divide_chunks(l, n))


def log(message, func=zono.colorlogger.log, *args, **kwargs):
    global VERBOSE
    if VERBOSE:
        func(message, *args, **kwargs)


def unzip(path, ext_to):
    with zipfile.ZipFile(path, "r") as ZIP:
        ZIP.extractall()


def parse_key(opts):
    global HASHED_KEY

    STRING_KEY = opts.key
    if opts.hash:
        HASHED_KEY = crypt.hashing_function(STRING_KEY, salt=b"")
        return

    if crypt.check_valid_key(STRING_KEY.encode("utf-8")):
        HASHED_KEY = STRING_KEY
    else:
        HASHED_KEY = crypt.hashing_function(STRING_KEY, salt=b"")


def _decrypt(enc, key):
    return crypt.decrypt_raw(enc, key)


def decrypt_folder(opts):
    split_encrypted = opts.file_bytes.split(b"&$&")
    log("Split encrypted bytes")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )

    log("Starting threads")
    decrypted_list = worker.run(split_encrypted, _decrypt, HASHED_KEY)
    log("Threads completed, decrypted chunks")
    file_bytes = b"".join(decrypted_list)
    os.mkdir("temp.encrypted")
    with open("temp.encrypted/temp.zip", "wb") as f:
        f.write(file_bytes)

    log("Written file")
    unzip("temp.encrypted/temp.zip", os.getcwd())
    log("Unzipped folder successfully")
    print(f"Decrypted file to {opts.filename}")
    log(f"time taken: {time.time()-opts.start_time}s", print)
    shutil.rmtree("temp.encrypted")


def decrypt_file(opts):
    split_encrypted = opts.file_bytes.split(b"&$&")
    log("Split encrypted bytes")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )

    log("Starting threads")
    decrypted_list = worker.run(split_encrypted, _decrypt, HASHED_KEY)
    log("Threads completed, decrypted chunks")
    file_bytes = b"".join(decrypted_list)
    with open(opts.output_file, "wb") as f:
        f.write(file_bytes)
    print(f"Decrypted file to {opts.output_file}")
    log(f"time taken: {time.time()-opts.start_time}s", print)


def decrypt_archived_file(opts):
    split_encrypted = opts.file_bytes.split(b"&$&")
    log("Split encrypted bytes")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )

    log("Starting threads")
    decrypted_list = worker.run(split_encrypted, _decrypt, HASHED_KEY)
    log("Threads completed, decrypted chunks")
    file_bytes = b"".join(decrypted_list)
    log("File decrypted")
    with open("temp_file.zip", "wb") as f:
        f.write(file_bytes)

    unzip("temp_file.zip", opts.output_file)
    log("Unzipped file")
    zono.colorlogger.major_log("File decrypted successfully")


def decrypt(opts):
    global HASHED_KEY
    opts.start_time = time.time()
    with open(opts.file, "rb") as f:
        file_bytes_enc = f.read()

    log("Loaded file")

    bytes_length = len(file_bytes_enc)
    file_type_start = file_bytes_enc.index(b"[")
    filetype_enc_ = file_bytes_enc[file_type_start:bytes_length].decode("utf-8")
    file_bytes = file_bytes_enc[0:file_type_start]
    opts.file_bytes = file_bytes
    filetype_enc = (
        filetype_enc_.replace("[", "")
        .replace("]", "")
        .replace("b'", "")
        .replace("'", "")
        .encode("utf-8")
    )

    try:
        filetype_dec = crypt.decrypt(filetype_enc, HASHED_KEY)
        log("Decrypted file type")

    except zono.zonocrypt.IncorrectDecryptionKey:
        zono.colorlogger.error("Incorrect decryption key")
        sys.exit()

    filename = filetype_dec.replace("$#ARCHIVED#$", "").replace("$#FOLDER#$", "")
    opts.output_file = opts.output_file or os.getcwd() + "/" + filename
    opts.filename = filename

    if "$#ARCHIVED#$" in filetype_dec:
        filetype_dec = filetype_dec.replace("$#ARCHIVED#$", "")
        log(f"Identified file type: Archived file with the name {filetype_dec}")
        decrypt_archived_file(opts)

    elif "$#FOLDER#$" in filetype_dec:
        filetype_dec = filetype_dec.replace("$#FOLDER#$", "")
        log(f"Identified file type: Folder with the name {filetype_dec}")
        decrypt_folder(opts)
    else:
        log(f"Identified file type: file type: {filetype_dec}")
        decrypt_file(opts)


pa = argparse.ArgumentParser("File decrypter", description="Decrypts files")


pa.add_argument("file", help="The file that should be encrypted")
pa.add_argument("key", help="The key used for decryption")

pa.add_argument(
    "--max-threads",
    help="Sets the maximum number of threads to use for decryption",
    default=32,
    type=int,
)


pa.add_argument("-v", "--verbose", action="store_true", help="Prints extra information")

pa.add_argument(
    "-replace", action="store_true", help="Replace existing file with decrypted version"
)

pa.add_argument("-of", "--output-file", help="Manually set the output file")
pa.add_argument(
    "-i", "--ignorewarnings", action="store_true", help="Ignores all warnings"
)

pa.add_argument(
    "--hash",
    action="store_true",
    help="Hash the key regardless of whether it is already valid",
)

sys.argv.pop(0)

opts = pa.parse_args(sys.argv)


if not os.path.exists(opts.file):
    pa.error("Input file does not exist")


VERBOSE = opts.verbose

parse_key(opts)

decrypt(opts)
