#!/usr/bin/env python3
from english_words import get_english_words_set
import zono.colorlogger
import zono.zonocrypt
import zono.workers
import subprocess
import argparse
import zipfile
import logging
import shutil
import random
import time
import sys
import os


english_words_set = list(get_english_words_set(["web2"], lower=True))

crypt = zono.zonocrypt.zonocrypt()
windows = sys.platform == "win32"
logger = zono.colorlogger.create_logger("encrypt")


def _divide_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i : i + n]


def chunks(l, n):
    return list(_divide_chunks(l, n))


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
    if opts.random_key:
        string_key = get_random_string()
        hashed_key = crypt.hashing_function(string_key, salt=b"")

    else:
        string_key = opts.key
        if opts.hash:
            hashed_key = crypt.hashing_function(string_key, salt=b"")
            return

        if crypt.check_valid_key(string_key.encode("utf-8")):
            hashed_key = string_key
        else:
            hashed_key = crypt.hashing_function(string_key, salt=b"")

    return (string_key, hashed_key)


def _encrypt(fbytes, key):
    return crypt.encrypt_bytes(fbytes, key)


def encrypt_folder(opts, hashed_key, string_key):
    opts.output_file = opts.output_file or opts.file + ".encrypted"
    start_time = time.time()
    file = "temps.encrypted/file_zip"
    os.makedirs("temps.encrypted")
    zip_dir(opts.file, file)
    logger.debug("Zipped folder")

    with open(file + ".zip", "rb") as f:
        file_bytes = f.read()

    logger.debug("Loaded compressed file")

    split_file_bytes = chunks(file_bytes, opts.chunk_size)
    logger.debug("Split folder into chunks")
    logger.debug("Starting threads")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )

    encrypted_chunks = worker.run(split_file_bytes, _encrypt, hashed_key)
    logger.debug("Encrypted chunks")
    enc_file_byte = b"&$&".join(encrypted_chunks)

    with open(opts.output_file, "wb") as f:
        f.write(enc_file_byte)

    enc_input_file = crypt.encrypt(opts.file + "$#FOLDER#$", hashed_key)

    with open(opts.output_file, "a") as f:
        f.write(f"[{enc_input_file}]")

    logger.important_log("File successfully encrypted")
    print(f"String key: {string_key}\nHashed key: {hashed_key.decode('utf-8')}")
    logger.print(f"time taken: {time.time()-start_time}s")

    shutil.rmtree("temps.encrypted")
    if opts.replace:
        shutil.rmtree(opts.file)


def encrypt_file(opts, hashed_key, string_key):
    input_file = os.path.basename(opts.file)
    input_file_enc = input_file
    opts.output_file = opts.output_file or input_file + ".encrypted"
    start_time = time.time()
    if opts.archive:
        file = "temps.encrypted/file_zip.zip"
        os.makedirs("temps.encrypted")
        write_zip(opts.file, file)
        logger.debug("Zipped file")
        opts.file = file
        input_file_enc += "$#ARCHIVED#$"

    with open(opts.file, "rb") as file:
        file_bytes = file.read()

    logger.debug("Loaded compressed file")

    split_file_bytes = chunks(file_bytes, opts.chunk_size)
    logger.debug("Split file into chunks")
    logger.debug("Starting threads")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )

    encrypted_chunks = worker.run(split_file_bytes, _encrypt, hashed_key)
    logger.debug("Encrypted chunks")
    enc_file_byte = b"&$&".join(encrypted_chunks)

    with open(opts.output_file, "wb") as f:
        f.write(enc_file_byte)

    enc_input_file = crypt.encrypt(input_file_enc.encode("utf-8"), hashed_key)

    with open(opts.output_file, "a") as f:
        f.write(f"[{enc_input_file}]")

    logger.important_log("File successfully encrypted")
    print(f"String key: {string_key}\nHashed key: {hashed_key.decode('utf-8')}")
    logger.print(f"time taken: {time.time()-start_time}s")
    if opts.archive:
        shutil.rmtree("temps.encrypted")
    if opts.replace:
        os.remove(opts.file)


def parse_args():
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
        "-archive",
        action="store_true",
        help="Compresses the input file before encryption",
    )
    pa.add_argument(
        "-replace",
        action="store_true",
        help="Replace existing file with encrypted version",
    )

    pa.add_argument(
        "-i", "--ignorewarnings", action="store_true", help="Ignores all warnings"
    )

    pa.add_argument("-of", "--output-file", help="Manually set the output file")

    pa.add_argument(
        "--hashing-function",
        help="Runs the inputed string through the hashing function",
        default=False,
        action="store_true",
    )

    pa.add_argument(
        "--max-threads",
        help="Sets the maximum number of threads to use for encryption",
        default=32,
        type=int,
    )

    pa.add_argument(
        "--chunk-size",
        help="Sets the chunk size for encryption",
        default=32768,
        type=int,
    )
    pa.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level (up to 2 times)",
    )

    opts = pa.parse_args()
    verbosity = min(2, opts.verbose)
    log_levels = [
        logging.ERROR,
        logging.INFO,
        logging.DEBUG,
    ]
    log_level = log_levels[verbosity]
    logger.setLevel(log_level)
    return opts, pa


def main():
    opts, pa = parse_args()
    if opts.hashing_function:
        hashed = crypt.hashing_function(opts.hashing_function, salt=b"").decode("utf-8")
        print(f"The hash for {opts.hashing_function} is {hashed}")
        return
    if not os.path.exists(opts.file):
        return pa.error("Input file does not exist")
    if not any([opts.random_key, opts.key]):
        print("No key provided a random key will be used")
        opts.random_key = True

    string_key, hashed_key = parse_key(opts)  # type: ignore

    if os.path.exists("temps.encrypted"):
        shutil.rmtree("temps.encrypted")
    if os.path.isdir(opts.file):
        encrypt_folder(opts, hashed_key, string_key)

    else:
        encrypt_file(opts, hashed_key, string_key)


if __name__ == "__main__":
    main()
