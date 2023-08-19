#!/usr/bin/env python3
import zono.colorlogger
import zono.zonocrypt
import zono.workers
import argparse
import zipfile
import logging
import shutil
import time
import sys
import os

crypt = zono.zonocrypt.zonocrypt()
logger = zono.colorlogger.create_logger("decrypt")


def _divide_chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i : i + n]


def chunks(l, n):
    return list(_divide_chunks(l, n))


def unzip(path):
    with zipfile.ZipFile(path, "r") as ZIP:
        ZIP.extractall()


def parse_key(opts):
    string_key = opts.key
    if opts.hash:
        hashed_key = crypt.hashing_function(string_key, salt=b"")
        return

    if crypt.check_valid_key(string_key.encode("utf-8")):
        hashed_key = string_key
    else:
        hashed_key = crypt.hashing_function(string_key, salt=b"")

    return hashed_key


def _decrypt(enc, key, worker):
    try:
        return crypt.decrypt_raw(enc, key)
    except zono.zonocrypt.IncorrectDecryptionKey:
        worker.stop()


def decrypt_folder(opts, hashed_key):
    split_encrypted = opts.file_bytes.split(b"&$&")
    logger.debug("Split encrypted bytes")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )

    logger.debug("Starting threads")
    decrypted_list = worker.run(split_encrypted, _decrypt, hashed_key, worker)
    if isinstance(decrypted_list, zono.workers.StoppedWorker):
        logger.error("Chunk decryption failed: incorrect key or corrupted file")
        return sys.exit()
    logger.debug("Threads completed, decrypted chunks")
    file_bytes = b"".join(decrypted_list)
    os.mkdir("temp.encrypted")
    with open("temp.encrypted/temp.zip", "wb") as f:
        f.write(file_bytes)

    logger.debug("Wrote to file")
    unzip("temp.encrypted/temp.zip")
    logger.debug("Unzipped folder successfully")
    print(f"Decrypted file to {opts.filename}")
    logger.info(f"time taken: {time.time()-opts.start_time}s", print)
    shutil.rmtree("temp.encrypted")


def decrypt_file(opts, hashed_key):
    split_encrypted = opts.file_bytes.split(b"&$&")
    logger.debug("Split encrypted bytes")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )
    logger.debug("Starting threads")
    decrypted_list = worker.run(split_encrypted, _decrypt, hashed_key, worker)
    if isinstance(decrypted_list, zono.workers.StoppedWorker):
        logger.error("Chunk decryption failed: incorrect key or corrupted file")
        return sys.exit()
    logger.debug("Threads completed, decrypted chunks")
    file_bytes = b"".join(decrypted_list)
    with open(opts.output_file, "wb") as f:
        f.write(file_bytes)
    print(f"Decrypted file to {opts.output_file}")
    logger.info(f"time taken: {time.time()-opts.start_time}s", print)


def decrypt_archived_file(opts, hashed_key):
    split_encrypted = opts.file_bytes.split(b"&$&")
    logger.debug("Split encrypted bytes")
    worker = zono.workers.ProgressWorkload(
        opts.max_threads, ordered_return=True, tqdm_opts=dict(unit="chunks")
    )
    logger.debug("Starting threads")
    decrypted_list = worker.run(split_encrypted, _decrypt, hashed_key, worker)
    if isinstance(decrypted_list, zono.workers.StoppedWorker):
        logger.error("Chunk decryption failed: incorrect key or corrupted file")
        return sys.exit()
    logger.debug("Threads completed, decrypted chunks")
    file_bytes = b"".join(decrypted_list)
    logger.debug("File decrypted")
    with open("temp_file.zip", "wb") as f:
        f.write(file_bytes)

    unzip("temp_file.zip")
    logger.debug("Unzipped file")
    logger.important_log("File decrypted successfully")


def decrypt(opts, hashed_key):
    opts.start_time = time.time()
    with open(opts.file, "rb") as f:
        file_bytes_enc = f.read()

    logger.debug("Loaded file")

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
        filetype_dec = crypt.decrypt(filetype_enc, hashed_key)
        logger.debug("Decrypted file type")

    except zono.zonocrypt.IncorrectDecryptionKey:
        zono.colorlogger.error("Incorrect decryption key")
        sys.exit()

    filename = filetype_dec.replace("$#ARCHIVED#$", "").replace("$#FOLDER#$", "")
    opts.output_file = opts.output_file or os.getcwd() + "/" + filename
    opts.filename = filename

    if "$#ARCHIVED#$" in filetype_dec:
        filetype_dec = filetype_dec.replace("$#ARCHIVED#$", "")
        logger.debug(
            f"Identified file type: Archived file with the name {filetype_dec}"
        )
        decrypt_archived_file(opts, hashed_key)

    elif "$#FOLDER#$" in filetype_dec:
        filetype_dec = filetype_dec.replace("$#FOLDER#$", "")
        logger.debug(f"Identified file type: Folder with the name {filetype_dec}")
        decrypt_folder(opts, hashed_key)
    else:
        logger.debug(f"Identified file type: file type: {filetype_dec}")
        decrypt_file(opts, hashed_key)


def parse_args():
    pa = argparse.ArgumentParser("File decrypter", description="Decrypts files")

    pa.add_argument("file", help="The file that should be encrypted")
    pa.add_argument("key", help="The key used for decryption")

    pa.add_argument(
        "--max-threads",
        help="Sets the maximum number of threads to use for decryption",
        default=32,
        type=int,
    )

    pa.add_argument(
        "-v", "--verbose", action="store_true", help="Prints extra information"
    )

    pa.add_argument(
        "-replace",
        action="store_true",
        help="Replace existing file with decrypted version",
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
    pa.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level (up to 2 times)",
    )

    verbosity = min(2, opts.verbose)
    log_levels = [
        logging.ERROR,
        logging.INFO,
        logging.DEBUG,
    ]
    log_level = log_levels[verbosity]
    logger.setLevel(log_level)

    opts = pa.parse_args()
    return opts, pa


def main():
    global VERBOSE
    opts, pa = parse_args()
    if not os.path.exists(opts.file):
        pa.error("Input file does not exist")

    if opts.output_file:
        if os.path.isdir(opts.output_file):
            pa.error("Cannot save to a directory")
    VERBOSE = opts.verbose

    hashed_key = parse_key(opts)
    decrypt(opts, hashed_key)


if __name__ == "__main__":
    main()
