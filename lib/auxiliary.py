#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os.path
import keyring
from datetime import datetime
import logging
LOGGING_FORMAT = "[%(levelname)s]\t%(asctime)s - %(message)s"


class Auxiliary():

    def __init__(self, options):

        self.options = options
        self.logfile = self.init_logger(options["log"])

        if self.options["csv"]: self.create_csv_files()

    
    def log(self, message, logger = None, level = "INFO"):
        if self.logfile == None:
            return

        if logger == None:
            logger = self.logfile

        if level.upper() == "INFO":
            logger.info(message)
        elif level.upper() == "WARNING":
            logger.warning(message)
        elif level.upper() == "ERROR":
            logger.error(message)
        elif level.upper() == "DEBUG":
            logger.debug(message)
        else:
            logger.info(message)


    def init_logger(self, logfile, formatting = "", write_mode = "w"):
        try:
            f = open(logfile, write_mode)
            f.close()
        except IOError:
            return None

        logger = logging.getLogger(logfile)
        logger.setLevel(logging.DEBUG)

        if formatting == "":
            formatting = LOGGING_FORMAT

        formatter = logging.Formatter(formatting)
        handler = logging.FileHandler(logfile)
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG)

        stream = logging.StreamHandler()
        stream.setLevel(logging.INFO)

        logger.addHandler(handler)
        logger.addHandler(stream)

        return logger


    def get_logger(self):
        return self.logfile


    def get_date(self):
        timestamp = (datetime.now().timestamp())
        
        return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d")


    def convert_timestamp(self, timestamp, format = "%Y-%m-%d %H:%M:%S", output_format = "%Y-%m-%d"):
        try:
            return datetime.strptime(timestamp, format).strftime(output_format)
        except TypeError:
            return None


    def process_api_key(self):
        """ Reads the VirusTotal API key from the system keyring (virustotal -> api_key).
            If it not stored yet, the user is prompted to provide her key.
        
            :return: The API key as a string
        """

        api_key = keyring.get_password('virustotal', 'api_key')
        message = ""
        if api_key is None:
            message = "VirusTotal API key is not yet stored in the system keyring."
        elif self.options["update_api_key"]:
            message = "The VirusTotal API key was requested to be updated."
        else:
            self.log("VirusTotal API key was read from the system keyring.", level = "DEBUG")
            return api_key

        self.log("{0}\nPlease note that you must specify an API key that is valid for the (commercial) Private API in order to fully use this program.\n".format(message), level = "WARNING")
        
        while True:
            try:
                key1  = input("Please enter the API key, or press Ctrl+C to abort:  ")
                key2  = input("Please verify the API key, or press Ctrl+C to abort: ")
                
                if key1.strip("\n ") == key2.strip("\n "):
                    api_key = key1.strip("\n ")
                    keyring.set_password("virustotal", "api_key", api_key)
                    self.log("VirusTotal API key was saved to the system keyring.", level = "DEBUG")
                    return api_key
            except KeyboardInterrupt:
                self.log("\n\nAPI key not entered. Program aborted.\n")
                sys.exit(0)


    def create_csv_header(self, filename, fields):

        try:
            file_handle = open(filename, "w")
            
            line = "#"
            for field in fields: line += "{0}{1}".format(field, self.options["separator"])
            file_handle.write("{0}\n".format(line[:-1]))
            
            return file_handle
        except IOError as err:
            self.options["auxiliary"].log("CSV file could not be created: {0}".format(filename), level = "ERROR")
            return None


    def create_csv_files(self):
        
        # saves a dictionary of file handles to CSV files
        self.options["csv_files"] = {}
        for item in self.options["filenames"]:
            filename = self.options["filenames"][item]
            if not filename.endswith(".csv"): continue
            
            fields = []
            # define header fields for each artifact type 
            if self.options["verbose"] < 3:
                if item == "file":
                    fields = ["SHA256", "MD5", "SHA1", "Vhash", "Size", "Type", "Tags", "First submitted on", "Last submitted on", "Times submitted", "Benign", "Malicious", "Suspicious", "Undetected"]
                elif item == "domain":
                    fields = ["Domain", "Registrar", "Tags", "Created on", "Last modified", "Last updated", "Benign", "Malicious", "Suspicious", "Undetected"]
                elif item == "url":
                    fields = ["URL", "Final URL", "Title", "Tags", "First submitted on", "Last submitted on", "Times submitted", "Benign", "Malicious", "Suspicious", "Undetected"]
            else:
                if item == "file":
                    fields = ["SHA256", "MD5", "SHA1", "Vhash", "Size", "Type", "Tags", "Vendor", "Signature", "Result", "Signature Database"]
                elif item == "domain":
                    fields = ["Domain", "Registrar", "Tags", "Vendor", "Signature", "Result", "Signature Database"]
                elif item == "url":
                    fields = ["URL", "Final URL", "Title", "Tags", "Vendor", "Signature", "Result", "Signature Database"]

            # network IOCs for a sample should be created regardless of the verbosity level
            if item == "network":
                fields = ["SHA256", "MD5", "SHA1", "Vhash", "Size", "Type", "Tags", "Host", "Port", "URL"]

            filename = os.path.join(self.options["csv_dir"], filename)
            file_handle = self.create_csv_header(filename, fields)
            self.options["csv_files"][item] = file_handle


    def close_csv_files(self):

        if "csv_files" not in self.options: return
        
        for filename in self.options["csv_files"]:
            if self.options["csv_files"][filename] is not None: 
                self.options["csv_files"][filename].close()

