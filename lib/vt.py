#!/usr/bin/env python3

import vt
import sys
import os.path
import json
import re
import requests
import asyncio

from .artifact import Artifact
from .sandboxes import Sandbox_Parser


class VirusTotal_Search(Artifact):
    """ Provides a class for running a VirusTotal Intelligence search and processing respective
        results.

        By default, at max 300 results are returned per query.
    """

    def __init__(self, options):

        super().__init__(options)
        
        self.options = options
        self.auxiliary = options["auxiliary"]


        self.site = {
                        
                        "url"       :   "https://virustotal.com/api/v3/",
                        "header"    :   {
                                            "x-apikey"  :   self.options["virustotal"]
                                        }
                    }

        self.client = vt.Client(self.options["virustotal"])
        
        # TODO: consolidate queues
        self.sample_queue = asyncio.Queue()
        self.behavior_queue = asyncio.Queue()
        self.info_queue = asyncio.Queue()


    async def search(self):
        """ Executes a VirusTotal Intelligence search
        """
        
        async with vt.Client(self.options["virustotal"]) as client:
            self.options["auxiliary"].log("Running intelligence query: {0}".format(self.options["query"]))
            it = client.iterator('/intelligence/search',  params={'query': self.options["query"]}, limit=self.options["limit"])
            
            artifact_log = os.path.join(self.options["download_dir"], self.options["filenames"]["artifacts"])

            tasks = []
            asyncio.create_task(self.get_heartbeat())
            with open(artifact_log, "w") as f:
                # iterate through the result set - each element represents a File object
                try:
                    async for obj in it:
                        if obj.type not in ["file", "url", "domain"]:
                            self.options["auxiliary"].log("Warning: Unknown artifact type detected: {0} - {1:70}".format(obj.type, obj.id), level="WARNING")
                            continue
                        
                        # log the name / identifier of the artifact
                        if obj.type in ["file", "domain"]:
                            f.write("{0}\n".format(obj.id))
                        elif obj.type == "url":
                            f.write("{0} => {1}\n".format(obj.id, obj.url)) 

                        # for samples, request downloading the artifact and behavior report
                        if obj.type == "file":
                            if self.options["download_samples"]  : await self.sample_queue.put(obj)
                            if self.options["download_behavior"] : await self.behavior_queue.put(obj)
                        
                        # save the report summary
                        sample_report = os.path.join(self.options["info_dir"], obj.id)
                        super().display_information(obj, sample_report)
                except vt.error.APIError as err:
                    
                    if err.code in ["AuthenticationRequiredError", "ForbiddenError", "UserNotActiveError", "WrongCredentialsError"]:
                        self.auxiliary.log("The API key is not valid for accessing the VirusTotal Private API, or there was a problem with the user account.", level = "ERROR")
                    elif err.code in ["QuotaExceededError", "TooManyRequestsError"]:
                        self.auxiliary.log("The quota for the API key or the number of issued requests has been exceeded.", level = "ERROR")
                    else:
                        self.auxiliary.log("There was an error while processing the request: {0}".format(err.code), level="ERROR")

                    return None

                    
                for worker in range(self.options["workers"]):
                    if self.options["download_behavior"]: tasks.append(asyncio.create_task(self.get_behavior_report()))
                    if self.options["download_samples"]: tasks.append(asyncio.create_task(self.get_sample()))
                            
                await asyncio.gather(*tasks)
                await self.behavior_queue.join()
                await self.sample_queue.join()
                for task in tasks: task.cancel()


    async def download_samples(self, filename):
        """ Reads in a list of hashes from a file for subsequent sample download

            :param filename: The name of the file that contains the list of hashes
        """
        
        md5 = re.compile(r"([a-fA-F\d]{32})")
        sha1 = re.compile(r"([a-fA-F\d]{40})")
        sha256 = re.compile(r"([a-fA-F\d]{64})")

        samples = []
        asyncio.create_task(self.get_heartbeat())
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
            result = tasks.append(asyncio.create_task(self.get_sample_info()))
                    
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


    async def execute_request(self, request):
        """ Runs an asynchronous call to retreive a behavioral report from VirusTotal
        
            :param request: The API request to execute

            :return:        JSON output that is contained in the 'data' field
        """

        async with vt.Client(self.options["virustotal"]) as client:
            try:
                url = requests.compat.urljoin(self.site["url"], request)
                result = await client.get_json_async(url)
                
                if "data" not in result:
                    raise ValueError("No valid JSON report received")
                
                return result["data"]
            except vt.error.APIError as err:
                return None
            except ValueError as err:
                self.options["auxiliary"].log("Behavior report for sample did not contain valid data: {0}".format(url))
                return None


    async def get_heartbeat(self):
        """ Periodically print a status message of the queue to indicate the number of pending tasks
        """

        while True:
            sys.stdout.write("\033[94m[Queue] Sample Reports: {0:03d} - Artifacts: {1:03d} - Behavior Reports: {2:03d}\033[0m\r".format(self.info_queue.qsize(), self.sample_queue.qsize(), self.behavior_queue.qsize()))
            sys.stdout.flush()
            await asyncio.sleep(1)


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
                    super().display_information(result, sample_report)

                    samples.append(result)
                except vt.error.APIError as err:
                    if err.code == "NotFoundError":
                        self.options["auxiliary"].log("Sample was not found: {0}\n".format(sample_id), level = "WARNING")
                        self.info_queue.task_done()
                        continue
                    elif err.code in ["AuthenticationRequiredError", "ForbiddenError", "UserNotActiveError", "WrongCredentialsError"]:
                        self.auxiliary.log("The API key is not valid for accessing the VirusTotal Private API, or there was a problem with the user account.", level = "ERROR")
                    elif err.code in ["QuotaExceededError", "TooManyRequestsError"]:
                        self.auxiliary.log("The quota for the API key or the number of issued requests has been exceeded.", level = "ERROR")
                    else:
                        self.auxiliary.log("There was an error while processing the request: {0}".format(err.code), level="ERROR")
                    
                    # clear all remaining items in the queue
                    while not self.info_queue.empty(): 
                        await self.info_queue.get()
                        self.info_queue.task_done()

                self.info_queue.task_done()

        return samples


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
                    url = 'files/{0}/behaviours'.format(sample_id)
                    result = await self.execute_request(url)
                    
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
                except IOError as err:
                    self.options["auxiliary"].log("Error while downloading sample: {0}".format(err), level = "ERROR")
                    self.sample_queue.task_done()
