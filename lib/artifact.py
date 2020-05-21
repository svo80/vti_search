#!/usr/bin/env python3

import os.path
import json

"""
    Super class for displaying information about an artifact and / or saving the information to
    an artifact report file on disk.

    
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
        "type_tag"              :   "Type",
        "tags"                  :   "Tag(s)",
        "magic"                 :   "File description",

        # domain attributes
        "creation_date"         :   "Creation date",
        "last_modification_date":   "Last modified",
        "last_update_date"      :   "Last updated",
        "registrar"             :   "Registrar",
        
        # url attributes
        "title"                 :   "Title",
        "last_final_url"        :   "Final URL",

        # attributes for scan results
        "harmless"              :   "Benign",
        "suspicious"            :   "Suspicious",
        "malicious"             :   "Malicious",
        "undetected"            :   "Undetected",
        "failure"               :   "Failure",
        "type-unsupported"      :   "Unsupported",
}


class Artifact():
    """ Provides a class for running a VirusTotal Intelligence search and processing respective
        results.

        By default, at max 300 results are returned per query.
    """

    def __init__(self, options):

        self.options = options
        self.auxiliary = options["auxiliary"]


    def display_scanning_results(self, sample, required_verbose_level = 0, file_handle = None):
        """ Displays scanning results per anti-virus vendor
            
            :param sample:                  The sample object
            :param required_verbose_level:  Displays results on screen if the verbose level
                                            is high enough, otherwise only logs results to a file
            :param file_handle:             If set, writes information to an artifact report file
        """

        results = sample.last_analysis_results
        for item in results:
            engine = results[item]
            
            # category can be, e.g., suspicious, malicious, undetected, etc. 
            category = KEYWORD_MAP[engine["category"]] if engine["category"] in KEYWORD_MAP else engine["category"]         
            signature = engine["result"] if engine["result"] is not None else "--"
            if len(signature) > 40: signature = "{0} (...)".format(signature[:40])

            if "engine_update" in engine and engine["engine_update"] is not None:
                signature_database = engine["engine_update"] 
            else:
                signature_database = "--"

            string = "{0}{1:28}{2:47}{3:25}(Signature Database: {4})".format(" " * 2, engine["engine_name"], signature, category, signature_database)
            if self.options["verbose"] >= required_verbose_level: print(string)
            if file_handle is not None: file_handle.write("{0}\n".format(string))

            if self.options["csv"] and self.options["verbose"] >= 3:
                line = ""
                attributes = dir(sample)

                if sample.type == "file":
                    fields = ["sha256", "md5", "sha1", "vhash", "size", "type_tag", "tags"]
                elif sample.type == "domain":
                    fields = ["id", "registrar", "tags"]
                elif sample.type == "url":
                    fields = ["url", "last_final_url", "title", "tags"]
                else:
                    fields = []

                for value in fields:
                    if value not in attributes:
                        line += self.options["separator"]
                        continue

                    if isinstance(getattr(sample, value), list):
                        list_items = ""
                        for item in getattr(sample, value):
                            list_items += "{0}|".format(item)
                        line += "\"{0}\"{1}".format(list_items[:-1], self.options["separator"])
                    else:
                        line += "\"{0}\"{1}".format(getattr(sample, value), self.options["separator"])
                for value in ["engine_name", "result", "category", "engine_update"]:

                    if value in engine and engine[value] is not None:
                        line += "\"{0}\"{1}".format(engine[value], self.options["separator"]) 
                    else:
                        line += "\"\"{0}".format(self.options["separator"])
                
                self.options["csv_files"][sample.type].write("{0}\n".format(line[:-1]))
                
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
            :param file_handle:             If set, writes information to an artifact report file
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
                line = ""
                for item in getattr(sample, value):
                    line += "{0}, ".format(item)
                label = KEYWORD_MAP[value] if value in KEYWORD_MAP else value

                string = "{0}{1:28}{2}".format(" " * 2, label + ":", line[:-2])
                if self.options["verbose"] >= required_verbose_level: print(string)
                if file_handle is not None: file_handle.write("{0}\n".format(string))
            else:
                label = KEYWORD_MAP[value] if value in KEYWORD_MAP else value
                string = "{0}{1:28}{2}".format(" " * 2, label + ":", getattr(sample, value))
                if self.options["verbose"] >= required_verbose_level: print(string)
                if file_handle is not None:  file_handle.write("{0}\n".format(string))

        if self.options["verbose"] >= required_verbose_level:  print("")
        if file_handle is not None: file_handle.write("\n")


    def display_information(self, sample, filename = None):
        """
            Displays information about an artifact that was returned as part of a search query.
            Displayed information is dependent on the artifact type.

            :param sample:   Sample object (type: file, domain, url)
            :param filename: Name of a report file
        """

        identifier = ""
        if sample.type in ["file", "domain"]:
            # INFO: For domains, the identifier is the domain name
            #       This appears to be okay, as for unicode characters an internationalized domain
            #       name is returned which should not cause any conflict with the file system level
            # TODO: check this with dedicated tests
            identifier = sample.id
        elif sample.type == "url":
            identifier = sample.url
        else:
            self.options["auxiliary"].log("Unknown sample type detected: {0} - {1}".format(sample.type, sample.id), level="WARNING")
        print("{0:80}".format(identifier))

        # write the summary information to disk if a filename was provided and the report
        # does not exist yet, otherwise only log but do not rewrite
        file_handle = None
        if (filename is not None) and (not os.path.exists(filename)): 
            file_handle = open(filename, "w")
            file_handle.write("{0}\n".format(identifier))
        elif (filename is not None) and (os.path.exists(filename)):
            self.options["auxiliary"].log("Summary report for the sample already exists on disk and is not downloaded again: {0}".format(sample.id), level = "DEBUG")
        
        # write the raw report to disk if a filename was provided and the report
        # does not exist yet, otherwise only log but do not rewrite
        raw_filename = "{0}.raw".format(filename)
        if (filename is not None) and (not os.path.exists(raw_filename)):
            try:
                with open(raw_filename, "w") as f:
                    json.dump(sample.to_dict(), f)
            except (IOError, TypeError) as err:
                self.options["auxiliary"].log("There was an error while saving the raw report to disk for sample: {0} - {1}".format(sample.id, err), level="ERROR")
        elif (filename is not None) and (os.path.exists(raw_filename)):
            self.options["auxiliary"].log("The raw report for the sample already exists on disk and is not downloaded again: {0}".format(sample.id), level = "DEBUG")


        if self.options["csv"] and self.options["verbose"] < 3:
            line = ""
            attributes = dir(sample)

            # determine output fields by artifact type
            fields = []
            if sample.type == "file":
                fields = ["sha256", "md5", "sha1", "vhash", "size", "type_tag", "tags", "first_submission_date", "last_submission_date", "times_submitted"]
            elif sample.type == "domain":
                fields = ["id", "registrar", "tags", "creation_date", "last_modification_date", "last_update_date"]
            elif sample.type == "url":
                fields = ["url", "last_final_url", "title", "tags", "first_submission_date", "last_submission_date", "times_submitted"]
            else:
                fields = []

            for value in fields: 
                if value not in attributes:
                    line += self.options["separator"]
                    continue

                if isinstance(getattr(sample, value), list):
                    list_items = ""
                    for item in getattr(sample, value):
                        list_items += "{0}|".format(item)
                    line += "\"{0}\"{1}".format(list_items[:-1], self.options["separator"])
                else:
                    line += "\"{0}\"{1}".format(getattr(sample, value), self.options["separator"])

            for value in ["harmless", "malicious", "suspicious", "undetected"]:
                if (("last_analysis_stats" in attributes) and (value in sample.last_analysis_stats.keys())):
                    line += "\"{0}\"{1}".format(sample.last_analysis_stats[value], self.options["separator"])
                else:
                    line += "\"{0}\"".format(self.options["separator"])

            self.options["csv_files"][sample.type].write("{0}\n".format(line[:-1]))
      
        # verbose level 1
        if sample.type == "file":
            values = ["md5", "sha1", "vhash"]
        elif sample.type == "domain":
            values = ["creation_date", "last_modification_date", "last_update_date"]
        elif sample.type == "url":
            values = ["last_final_url", "title"]
        else:
            values = []
        self.display_values(values, sample, required_verbose_level = 1, file_handle = file_handle)
        
        values = ["magic", "type_tag", "tags", "size"]
        self.display_values(values, sample, required_verbose_level = 1, file_handle = file_handle)

        # verbose level 2
        if sample.type in ["file", "url"]:
            values = ["first_submission_date", "last_submission_date", "times_submitted", "unique_sources"]
        elif sample.type == "domain":
            values = ["registrar"]
        else:
            values = []
        self.display_values(values, sample, required_verbose_level = 2, file_handle = file_handle)
   
        values = ["last_analysis_stats"]
        self.display_values(values, sample, ["harmless", "malicious", "suspicious", "undetected"], required_verbose_level = 1, file_handle = file_handle)

        # verbose level 3
        self.display_scanning_results(sample, required_verbose_level = 3, file_handle = file_handle)

        if file_handle is not None: 
            file_handle.close()
            self.options["auxiliary"].log("Saved summary report: {0}".format(filename), level = "DEBUG")



