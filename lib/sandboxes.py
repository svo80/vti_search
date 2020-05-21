#!/usr/bin/env python3

import sys
import os.path

class Sandbox_Parser():

        def __init__(self, options, report):
            """ 
                :param report: A (collection of) sandbox report(s) in JSON format
            """

            self.options = options
            self.report = report

            self.auxiliary = options["auxiliary"]


        def parse_report(self, sample, required_verbose_level = 1):
            """ Parses the (list of) sandbox report(s) that are defined in a dynamic analysis 
                collection, and extracts the network indicators

                :param sample: A sample object
            """

            traffic_objects = []
            verbose_level = "INFO" if self.options["verbose"] >= required_verbose_level else "DEBUG"
            
            for sandbox in self.report:
                if "attributes" not in sandbox or "sandbox_name" not in sandbox["attributes"]: continue
                data = sandbox["attributes"]
                attributes = dir(sample)
                
                # extract unique network indicators across all sandbox reports
                if "ip_traffic" in data:
                    traffic = data["ip_traffic"]
                    for item in traffic:
                        # only consider UDP or TCP connections
                        if ("transport_layer_protocol" not in item) or (("transport_layer_protocol" in item) and (item["transport_layer_protocol"] not in ["UDP", "TCP"])):
                            continue

                        if "{0}:{1}".format(item["destination_ip"], item["destination_port"]) not in traffic_objects:
                            if self.options["csv"]:
                                line = ""
                                for value in ["sha256", "md5", "sha1", "vhash", "size", "type_tag", "tags"]:
                                    if value not in attributes:
                                        line += self.options["separator"]
                                        continue
                                    
                                    if isinstance(getattr(sample, value), list):
                                        list_items = ""
                                        for list_item in getattr(sample, value):
                                            list_items += "{0}, ".format(list_item)
                                        line += "\"{0}\"{1}".format(list_items[:-2], self.options["separator"])
                                    else:
                                        line += "\"{0}\"{1}".format(getattr(sample, value), self.options["separator"])

                                for value in ["destination_ip", "destination_port", "url"]:
                                    line += "\"{0}\"{1}".format(item[value], self.options["separator"]) if (value in item) and (item[value] is not None) else "\"\"{0}".format(self.options["separator"])
                                self.options["csv_files"]["network"].write("{0}\n".format(line[:-1]))

                            # TODO: Should we only add the host or host:port information?
                            traffic_objects.append("{0}:{1}".format(item["destination_ip"], item["destination_port"]))

                # extract unique URLs across all sandbox reports
                if "http_conversations" in data:
                    traffic = data["http_conversations"]
                    for item in traffic:
                        if item["url"] not in traffic_objects:
                            if self.options["csv"]:
                                line = ""
                                for value in ["sha256", "md5", "sha1", "vhash", "size", "type_tag", "tags"]:
                                    if value not in attributes:
                                        line += self.options["separator"] 
                                        continue
                                    
                                    if isinstance(getattr(sample, value), list):
                                        list_items = ""
                                        for list_item in getattr(sample, value):
                                            list_items += "{0}|".format(list_item)
                                        line += "\"{0}\"{1}".format(list_items[:-2], self.options["separator"])
                                    else:
                                        line += "\"{0}\"{1}".format(getattr(sample, value), self.options["separator"])

                                for value in ["destination_ip", "destination_port", "url"]:
                                    line += "\"{0}\"{1}".format(item[value], self.options["separator"]) if (value in item) and (item[value] is not None) else "\"\"{0}".format(self.options["separator"])
                                self.options["csv_files"]["network"].write("{0}\n".format(line[:-1]))

                            traffic_objects.append(item["url"])

            # if network indicators were extracted, write the information to an indicator report
            # (unless it is not existing already)
            filename = os.path.join(self.options["info_dir"], "{0}.ioc".format(sample.id))
            if (len(traffic_objects) > 0) and (not os.path.exists(filename)): 
                with open(filename, "a") as f:
                    [ f.write("{0}\n".format(item)) for item in traffic_objects ]
            elif (len(traffic_objects) > 0) and (os.path.exists(filename)):
                self.options["auxiliary"].log("Network indicator report for sample already exists on disk: {0}".format(sample.id), level = "DEBUG")
            else:
                #self.options["auxiliary"].log("No network indicators found for sample: {0}".format(sample.id), level = "DEBUG")
                pass

