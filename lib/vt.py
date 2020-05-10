#!/usr/bin/env python3

import vt
import requests
import sys
import os.path
import json
import re
import asyncio

from .sandboxes import Sandbox_Parser

"""
    Keywords and description:
    https://developers.virustotal.com/v3.0/reference#files  

    - Hashes like md5, sha1 and sha256 that identifies it
    - size of the file
    - first_submission_date when the file was first received in VirusTotal (as a UNIX timestamp)
    - last_submission_date last time we received it (as a UNIX timestamp)
    - last_analysis_date last time we analysed it (as a UNIX timestamp)
    - last_modification_date last time the object itself was modified (as a UNIX timestamp)
    - times_submitted how many times VirusTotal had received it
    - last_analysis_results: result of the last analysis. 
        
        dict with AV name as key and a dict with notes/result from that scanner as value.
        category: normalized result. can be:
        
        - "harmless" (AV thinks the file is not malicious),
        - "undetected" (AV has no opinion about this file),
        - "suspicious" (AV thinks the file is suspicious),
        - "malicious" (AV thinks the file is malicious).

    - names we have seen the file with, being meaningful_name the one we consider more interesting
    - unique_sources indicates from how many different sources the file has been received


    In the attributes dictionary you are going to find also fields with information extracted from the file itself. We characterise the file and expose this information in the following keys:

    - type_description describe the type of file it is, being type_tag it short and you can use to search files of the same kind.
    - creation_date is extracted when possible from the file and indicates the timestamp the compilation or build tool give to it when created, it can be also faked by malware creators.
    - total_votes received from the VirusTotal community, each time a user vote a file it is reflected in this values. reputation field is calculated from the votes the file received and the users reputations credits.
    - vhash an in-house similarity clustering algorithm value, based on a simple structural feature hash allows you to find similar files
    - tags are extracted from different parts of the report and are labels that help you search similar samples

    Additionally VirusTotal together with each Antivirus scan runs a set of tool that allows us to collect more information about the file. All this tool information is included in the "attributes" key, together with the rest of fields previously described.

"""

# Translation map for internal objects
KEYWORD_MAP = {
        # file attributes
        "md5"                   :   "MD5",
        "sha1"                  :   "Sha1",
        "vhash"                 :   "VHash",
        "first_submission_date" :   "First submission",
        "last_submission_date"  :   "Last submission",
        "times_submitted"       :   "Number of submissions",
        "unique_sources"        :   "Unique sources",
        "size"                  :   "Size",
        "type_tag"              :   "Type Tag",
        "magic"                 :   "Type",

        # attributes for scan results
        "harmless"              :   "Benign",
        "suspicious"            :   "Suspicious",
        "malicious"             :   "Malicious",
        "undetected"            :   "Undetected",
        "failure"               :   "Failure",
        "type-unsupported"      :   "Unsupported",
}


class VirusTotal_Search():
    """ Provides a class for running a VirusTotal Intelligence search and processing respective
        results.

        By default, at max 300 results are returned per query.
    """

    def __init__(self, options):

        self.options = options
        self.auxiliary = options["auxiliary"]

        self.site = {
                        
                        "url"       :   "https://virustotal.com/api/v3/",
                        "header"    :   {
                                            "x-apikey"  :   self.options["virustotal"]
                                        }
                    }

        self.client = vt.Client(self.options["virustotal"])
        
        self.sample_queue = asyncio.Queue()
        self.behavior_queue = asyncio.Queue()
        self.info_queue = asyncio.Queue()


    def display_scanning_results(self, sample, required_verbose_level = 0, file_handle = None):
        """ Displays scanning results per anti-virus vendor

            :param results: A dictionary of scan results saved in last_analysis_results
        """

        results = sample.last_analysis_results

        verbose_level = "INFO" if self.options["verbose"] >= required_verbose_level else "DEBUG"
        for item in results:
            engine = results[item]
            # category can be, e.g., suspicious, malicious, undetected, etc. 
            category = KEYWORD_MAP[engine["category"]] if engine["category"] in KEYWORD_MAP else engine["category"]         
            signature = engine["result"] if engine["result"] is not None else "--"
            if len(signature) > 40: signature = "{0} (...)".format(signature[:40])

            string = "{0}{1:28}{2:47}{3:25}(Signature Database: {4})".format(" " * 2, engine["engine_name"], signature, category, engine["engine_update"])
            if self.options["verbose"] >= required_verbose_level: print(string)
            if file_handle is not None: file_handle.write("{0}\n".format(string))

            if self.options["csv"] and self.options["verbose"] >= 3:
                line = ""
                for value in ["sha256", "md5", "sha1", "vhash", "size", "type_tag"]: 
                    line += "{0};".format(getattr(sample, value)) if value in dir(sample) else ";"
                for value in ["engine_name", "result", "category", "engine_update"]:
                    line += "{0};".format(engine[value]) if engine[value] is not None else ";"
                
                self.options["csv_files"]["search"].write("{0}\n".format(line[:-1]))
                
        if self.options["verbose"] >= required_verbose_level: print()
        if file_handle is not None: file_handle.write("\n")


    def display_values(self, id_list, sample, filter_values = None, required_verbose_level = 0, file_handle = None):
        """
            :param id_list:                 List of attributes that should be processed
            :param sample:                  The sample object
            :param filter_values:           White list of values that should be exclusively considered
                                            when parsing an attribute list
            :param required_verbose_level:  Displays results on screen if the verbose level
                                            is high enough, otherwise only logs results to a file
        """

        for value in id_list:
            if value not in dir(sample): continue
            
            if isinstance(getattr(sample, value), dict):
                for item in getattr(sample, value):
                    if filter_values is not None and isinstance(filter_values, list):
                        if item not in filter_values: continue

                    label = KEYWORD_MAP[item] if item in KEYWORD_MAP else item

                    string = "{0}{1:28}{2}".format(" " * 2, label + ":", getattr(sample, value)[item])
                    if self.options["verbose"] >= required_verbose_level: print(string)
                    if file_handle is not None: file_handle.write("{0}\n".format(string))
            elif isinstance(getattr(sample, value), list):
                self.auxiliary.log("Unparsed list: {0} - {1} ({2})".format(sample.sha256, getattr(sample, value), type(getattr(sample, value))), level = "ERROR")
            else:
                label = KEYWORD_MAP[value] if value in KEYWORD_MAP else value
                string = "{0}{1:28}{2}".format(" " * 2, label + ":", getattr(sample, value))
                if self.options["verbose"] >= required_verbose_level: print(string)
                if file_handle is not None:  file_handle.write("{0}\n".format(string))

        if self.options["verbose"] >= required_verbose_level:  print("")
        if file_handle is not None: file_handle.write("\n")


    def display_information(self, sample, filename = None):
        """
            Displays information about a sample that was returned as part of a search query

            :param sample: Sample object
        """

        print("{0:80}".format(sample.sha256))
        file_handle = None
        # write the summary information to disk if a filename was provided and the report
        # does not exist yet, otherwise only display the information on the console
        if (filename is not None) and (not os.path.exists(filename)): 
            file_handle = open(filename, "w")
            file_handle.write("{0}\n".format(sample.sha256))
        elif (filename is not None) and (os.path.exists(filename)):
            self.options["auxiliary"].log("Summary report for sample already exists on disk and is not downloaded again: {0}".format(sample.id), level = "DEBUG")

        if self.options["csv"] and self.options["verbose"] < 3:
            line = ""
            attributes = dir(sample)
            for value in ["sha256", "md5", "sha1", "vhash", "size", "type_tag", "first_submission_date", "last_submission_date", "times_submitted", "malicious", "suspicious", "undetected"]: 
                line += "{0};".format(getattr(sample, value)) if value in attributes else ";"
            self.options["csv_files"]["search"].write("{0}\n".format(line[:-1]))
        
        values = ["md5", "sha1", "vhash"]
        self.display_values(values, sample, required_verbose_level = 1, file_handle = file_handle)
        
        values = ["magic", "type_tag", "size"]
        self.display_values(values, sample, required_verbose_level = 1, file_handle = file_handle)

        values = ["first_submission_date", "last_submission_date", "times_submitted", "unique_sources"]
        self.display_values(values, sample, required_verbose_level = 2, file_handle = file_handle)
   
        values = ["last_analysis_stats"]
        self.display_values(values, sample, ["malicious", "suspicious", "undetected"], required_verbose_level = 1, file_handle = file_handle)

        self.display_scanning_results(sample, required_verbose_level = 3, file_handle = file_handle)

        if file_handle is not None: 
            file_handle.close()
            self.options["auxiliary"].log("Saved summary report: {0}".format(filename), level = "DEBUG")


    async def search(self):
        """ Executes a VirusTotal Intelligence search
        """
        
        async with vt.Client(self.options["virustotal"]) as client:
            self.options["auxiliary"].log("Running intelligence query: {0}".format(self.options["query"]))
            it = client.iterator('/intelligence/search',  params={'query': self.options["query"]}, limit=self.options["limit"])
            
            sample_log = os.path.join(self.options["download_dir"], "samples.txt")

            tasks = []
            with open(sample_log, "w") as f:
                # iterate through the result set - each element represents a File object
                async for obj in it:
                    f.write("{0}\n".format(obj.id))
                    
                    if self.options["download_samples"]  : await self.sample_queue.put(obj)
                    if self.options["download_behavior"] : await self.behavior_queue.put(obj)
                   
                    sample_report = os.path.join(self.options["info_dir"], obj.id)
                    self.display_information(obj, sample_report)
            
                for worker in range(self.options["workers"]):
                    asyncio.create_task(self.get_heartbeat())
                    if self.options["download_behavior"]: tasks.append(asyncio.create_task(self.get_behavior_report()))
                    if self.options["download_samples"]: tasks.append(asyncio.create_task(self.get_sample()))
                            
                await asyncio.gather(*tasks)
                await self.behavior_queue.join()
                await self.sample_queue.join()
                for task in tasks: task.cancel()


    def execute_request(self, request):
        """ Generic function for interacting with the VirusTotal API via the requests module

            This function is necessary as the results of not all VirusTotal interfaces can be
            (apparently) parsed via the iterator or get_object method.

            :param request: The API request to execute

            :return:        JSON output that is contained in the 'data' field
        """

        url = requests.compat.urljoin(self.site["url"], request)
                
        result = None
        try:
            req = requests.get(url, headers=self.site["header"])
            
            # raise an error if the status code is not 200, otherwise fetch the JSON output
            req.raise_for_status()
            result = req.json()

            if "data" not in result:
                raise requests.exceptions.RequestException
            
            result = result["data"]
        except requests.exceptions.HTTPError as err:
            # the item is not available or could not be read
            pass
        except requests.exceptions.ConnectionError:
            self.auxiliary.log("Network unreable.", level = "ERROR")
        except requests.exceptions.RequestException as err:
            self.auxiliary.log("Unknown error: {0}".format(err), level = "ERROR")

        return result


    async def get_heartbeat(self):
        """ Periodically print a status message of the queue to indicate the number of pending tasks
        """

        while True:
            if (self.info_queue.qsize() > 0) or (self.sample_queue.qsize() > 0) or (self.behavior_queue.qsize() > 0):
                sys.stdout.write("\033[94m[Queue] Sample Reports: {0:03d} - Artifacts: {1:03d} - Behavior Reports: {2:03d}\033[0m\r".format(self.info_queue.qsize(), self.sample_queue.qsize(), self.behavior_queue.qsize()))
                sys.stdout.flush()
            await asyncio.sleep(1)


    async def get_behavior_report(self):
        """ Retrieves a behavior report from VirusTotal
            (The behavior report can consist of a result list from multiple sandboxes)

            :return:            True if the report was successfully downloaded or was successfully
                                read from disk (if existing), otherwise False
        """

        async with vt.Client(self.options["virustotal"]) as client:
            while not self.behavior_queue.empty():
                sample = await self.behavior_queue.get()
                sample_id = sample if isinstance(sample, str) else sample.id
                
                # check if a sample object rather than a hash was provided
                report_file = os.path.join(self.options["reports_dir"], sample_id) 
                report_retrieved = False

                # if the report file is not on disk yet, it is downloaded
                if not os.path.isfile(report_file):
                    # TODO: asynchronous download required
                    url = 'files/{0}/behaviours'.format(sample_id)
                    result = self.execute_request(url)

                    if result is None:
                        self.options["auxiliary"].log("Sample does not have a behavior report, or the report could not be retrieved: {0}".format(sample_id), level="ERROR")
                        self.behavior_queue.task_done()
                        continue
                    try:
                        with open(report_file, "w") as f:
                            json.dump(result, f)
        
                        self.options["auxiliary"].log("Saved behaviorial report: {0}".format(report_file), level = "DEBUG")
                        report_retrieved = True
                    except IOError as err:
                        self.options["auxiliary"].log("Error while saving behaviorial report: {0} - {1}".format(report_file, err), level = "ERROR")
                else:
                    # the report has already been downloaded and is stored on disk
                    self.options["auxiliary"].log("Behavior report for sample already exists on disk and is not downloaded again: {0}".format(sample_id), level = "DEBUG")
            
                    try:  
                        with open(report_file, "r") as f:
                            result = json.load(f)

                        report_retrieved = True
                    except (IOError, json.JSONDecodeError) as err:
                        self.options["auxiliary"].log("Error while reading behaviorial report: {0} - {1}".format(report_file, err), level = "ERROR")

                if report_retrieved:
                    sandbox = Sandbox_Parser(self.options, result)
                    sandbox.parse_report(sample)

                self.behavior_queue.task_done()
                        

    async def download_samples(self, filename):
        """ Reads in a list of hashes from a file for subsequent sample download

            :param filename: The name of the file that contains the list of hashes
        """
        
        md5 = re.compile(r"([a-fA-F\d]{32})")
        sha1 = re.compile(r"([a-fA-F\d]{40})")
        sha256 = re.compile(r"([a-fA-F\d]{64})")

        asyncio.create_task(self.get_heartbeat())
        
        samples = []
        with open(filename, "r") as f:
            for data in f:
                data = data.strip("\n ")
                if md5.match(data) or sha1.match(data) or sha256.match(data):
                    # if the entry in the file represents a sample by hash, and the 
                    # sample is appearing for the first time, add it to the queue
                    if data not in samples:
                        await self.info_queue.put(data)
                        samples.append(data)

        # retrieve summary information and check if the sample exists
        tasks = []
        for worker in range(self.options["workers"]):
            tasks.append(asyncio.create_task(self.get_sample_info()))
                    
        results = await asyncio.gather(*tasks)
        await self.info_queue.join()
        for task in tasks: task.cancel()

        # download artifacts that are existing as well as corresponding behavior reports
        for worker in results:
            for sample in worker:
                if sample is not None:
                    if self.options["download_samples"]  : await self.sample_queue.put(sample)
                    if self.options["download_behavior"] : await self.behavior_queue.put(sample)

        tasks = []
        for worker in range(self.options["workers"]):
            if self.options["download_behavior"]: tasks.append(asyncio.create_task(self.get_behavior_report()))
            if self.options["download_samples"]: tasks.append(asyncio.create_task(self.get_sample()))
                    
        await asyncio.gather(*tasks)
        await self.behavior_queue.join()
        await self.sample_queue.join()
        for task in tasks: task.cancel()


    async def get_sample_info(self):
        """ Retrieves summary information about a sample
        """
        
        samples = []
        async with vt.Client(self.options["virustotal"]) as client:
            while not self.info_queue.empty():
                try:
                    sample_id = await self.info_queue.get()
                    path = os.path.join("/files", sample_id)
                    
                    # this call should be always performed to check if the sample exists
                    # and get context information for a hash value
                    result = await client.get_object_async(path)

                    sample_report = os.path.join(self.options["info_dir"], sample_id)
                    self.display_information(result, sample_report)

                    samples.append(result)
                except vt.error.APIError:
                    self.options["auxiliary"].log("Sample was not found: {0}\n".format(sample_id), level = "WARNING")

                self.info_queue.task_done()

        return samples


    async def get_sample(self):
        """ Downloads a sample from VirusTotal

            :param sample_id:   The id (hash value) of the sample
            
            :return:            True if the sample was successfully downloaded, otherwise False
                                (In case the sample already exists on disk, the return value
                                is also False)
        """
        
        async with vt.Client(self.options["virustotal"]) as client:
            while not self.sample_queue.empty():
                try:
                    sample_id = await self.sample_queue.get()
                    # check if a sample object rather than a hash was provided
                    if not isinstance(sample_id, str): sample_id = sample_id.id
                    
                    sample_path = os.path.join(self.options["samples_dir"], sample_id)
                    
                    # if the file is already on disk, it is not downloaded again
                    # TODO: Possibly check more than purely the filename to be sure the content was previously
                    #       correctly downloaded as well?  
                    if os.path.isfile(sample_path): 
                        self.options["auxiliary"].log("Sample already exists on disk and is not downloaded again: {0}".format(sample_id), level = "DEBUG")
                        self.sample_queue.task_done()
                        continue
                    
                    # save the sample to disk
                    with open(sample_path, "wb") as f:
                        await client.download_file_async(sample_id, f)
                        self.options["auxiliary"].log("Successfully downloaded sample: {0}".format(sample_id), level = "DEBUG")

                    self.sample_queue.task_done()
                    continue
                except IOError as err:
                    self.options["auxiliary"].log("Error while downloading sample: {0}".format(err), level = "ERROR")
                    self.sample_queue.task_done()
                    continue
