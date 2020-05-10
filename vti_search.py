#!/usr/bin/env python3
# coding=utf-8

import sys 
import argparse
import os
import os.path
import asyncio
from datetime import datetime
from lib import auxiliary, vt

meta =  {
            "title"     :   "VTISearch - VirusTotal Intelligence Search",
            "note"      :   "Written by Stefan Voemel.",
            "version"   :   "0.1.0",
        }


def get_header():
    print("\n{0} - Version {1}\n\n{2}".format(meta["title"], meta["version"], meta["note"]))
    print("{0}\n".format("-" * 90))


async def main():

    global options 
    
    # get the full path of the program module
    module_name = os.path.abspath(__file__)
    module_path = os.path.dirname(module_name)

    opt = argparse.ArgumentParser(epilog = get_header())

    opt.add_argument("-q", "--query", default="", dest="query",
        help="VirusTotal Intelligence query.")
    
    opt.add_argument("-l", "--limit", type=int, default=20, dest="limit",
        help="Limits the number of samples to return.")

    opt.add_argument("--logfile", type=str, default="log.txt", dest="log",
        help="Name of the log file.")
    
    opt.add_argument("--download-dir", type=str, default="", dest="download_dir",
        help="Name of the directory where retrieved information will be stored in.")
    
    opt.add_argument("-d", "--download", action="store_true", dest="download_samples",
        help="If set, also downloads samples from VirusTotal that are referenced in an Intelligence search.")
    
    opt.add_argument("-f", "--file", default="", dest="sample_file",
        help="Downloads samples that are referenced in a file.")

    opt.add_argument("--no-behavior", action="store_false", dest="download_behavior",
        help="If set, does not download behavior reports for samples.")
 
    opt.add_argument("-v", "--verbose", action="count", default=0, dest="verbose",
        help="If set, display verbose information about reports.\nUse -vvv to see detailed scan results.")
    
    opt.add_argument("-w", "--workers", type=int, default=5, dest="workers",
        help="Number of concurrent workers.")
   
    opt.add_argument("--csv", action="store_true", dest="csv",
        help="If set, display results as comma-separated values.")
    
    options = vars(opt.parse_args())
   
    if (len(options["query"]) == 0) and (len(options["sample_file"]) == 0):
        print("Please either specify a VirusTotal Intelligece search query or a file with sample hashes.")
        sys.exit(1)

    # create a new directory based on the current timestamp that will store all query- and 
    # download-related information
    if len(options["download_dir"]) == 0:
        timestamp = (datetime.now().timestamp())
        timestamp = datetime.fromtimestamp(timestamp).strftime("%Y%m%d_%H%M")

        options["download_dir"] = os.path.join(module_path, "downloads", timestamp)

    options["samples_dir"] = os.path.join(options["download_dir"], "samples")
    options["reports_dir"] = os.path.join(options["download_dir"], "reports")
    options["log"] = os.path.join(options["download_dir"], options["log"])

    # create directories if necessary
    created = True
    for directory in ["download_dir", "samples_dir", "reports_dir"]:
        try:
            os.makedirs(options[directory])
        except FileExistsError as err:
            pass
        except OSError as err:
            print("Error while creating directory: {0}".format(err))
            created = False
    if not created: sys.exit(-1)
    
    helper = auxiliary.Auxiliary(options)
    options["auxiliary"] = helper

    # get / save API key from / to the system keyring
    options["virustotal"] = options["auxiliary"].process_api_key()

    # start interaction with the VirusTotal service
    virustotal = vt.VirusTotal_Search(options)

    tasks = []
    # perform an Intelligence search (and download respective samples if indicated)
    if len(options["query"]) > 0:
        tasks.append(asyncio.create_task(virustotal.search()))
       
    # download samples that are referenced in a file
    if (len(options["sample_file"]) > 0) and (os.path.isfile(options["sample_file"])):
        tasks.append(asyncio.create_task(virustotal.download_samples(options["sample_file"])))
        
        for worker in range(options["workers"]):
            tasks.append(asyncio.create_task(virustotal.get_sample()))
        
    await asyncio.gather(*tasks)
    await virustotal.sample_queue.join()
    await virustotal.behavior_queue.join()
    for task in tasks:
        task.cancel()

    options["auxiliary"].log("\nInformation saved to {0}.".format(options["download_dir"]))
    
    if options["csv"]: options["auxiliary"].close_csv_files()


if __name__ == "__main__":
    asyncio.run(main())
