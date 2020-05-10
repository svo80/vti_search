#!/usr/bin/env python3
# -*- coding: utf-8 -*-

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

        if api_key is None:
            self.log("VirusTotal API key is not yet stored in the system keyring.\nPlease note that you must specify an API key that is valid for the Private API in order to fully use this program.\n", level = "WARNING")
            while True:
                key1  = input("Please enter the API key:  ")
                key2  = input("Please verify the API key: ")
                
                if key1.strip("\n ") == key2.strip("\n "):
                    api_key = key1.strip("\n ")
                    keyring.set_password("virustotal", "api_key", api_key)
                    self.log("VirusTotal API key was saved to the system keyring.", level = "DEBUG")
                    return api_key
        else:
            self.log("VirusTotal API key was read from the system keyring.", level = "DEBUG")
            return api_key


    def create_csv_files(self):

        # saves a dictionary of file handles to CSV files
        self.options["csv_files"] = {}

        #if len(self.options["query"]) > 0:
        # CSV file for Intelligence search results
        filename = os.path.join(self.options["download_dir"], "search.csv")
        csv_search = open(filename, "w")

        if self.options["verbose"] < 3:
            fields = ["SHA256", "MD5", "SHA1", "Vhash", "Size", "Type", "First submitted on", "Last submitted on", "Times submitted", "Malicious", "Suspicious", "Undetected"]
        else:
            fields = ["SHA256", "MD5", "SHA1", "Vhash", "Size", "Type", "Vendor", "Signature", "Result", "Signature Database"]

        line = "#"
        for field in fields: line += "{0};".format(field)
        csv_search.write("{0}\n".format(line[:-1]))
        self.options["csv_files"]["search"] = csv_search
        
        
        # CSV file for network indicators
        if self.options["download_behavior"]:
            filename = os.path.join(self.options["download_dir"], "network.csv")
            csv_network = open(filename, "w")

            fields = ["SHA256", "MD5", "SHA1", "Vhash", "Size", "Type", "Host", "Port", "URL"]

            line = "#"
            for field in fields: line += "{0};".format(field)
            csv_network.write("{0}\n".format(line[:-1]))
            self.options["csv_files"]["network"] = csv_network


    def close_csv_files(self):

        if "csv_files" not in self.options: return
        
        for filename in self.options["csv_files"]:
            self.options["csv_files"][filename].close()

