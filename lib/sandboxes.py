#!/usr/bin/env python3

import sys

class Sandbox_Parser():

        def __init__(self, options, report):

            self.options = options
            self.report = report

            self.auxiliary = options["auxiliary"]


        def parse_report(self, sample, required_verbose_level = 3):
            """ Parses the (list of) sandbox report(s) that are defined in a dynamic analysis 
                collection, and extracts the network indicators

                :param sample: A sample object
            """

            traffic_objects = []
            verbose_level = "INFO" if self.options["verbose"] >= required_verbose_level else "DEBUG"
            for sandbox in self.report:
                if "attributes" not in sandbox or "sandbox_name" not in sandbox["attributes"]: continue
                data = sandbox["attributes"]
                
                # extract network indicators
                if "ip_traffic" in data:
                    traffic = data["ip_traffic"]
                    for item in traffic:
                        if item["destination_ip"] not in traffic_objects:
                            self.options["auxiliary"].log("{0}{1:27} {2}:{3}".format(" " * 2, "[Host]", item["destination_ip"], item["destination_port"]), level = verbose_level)

                            if self.options["csv"]:
                                line = ""
                                for value in ["sha256", "md5", "sha1", "vhash", "size", "type_tag"]:
                                    line += "{0};".format(getattr(sample, value)) if value in dir(sample) else ";"
                                for value in ["destination_ip", "destination_port", "url"]:
                                    line += "{0};".format(item[value]) if (value in item) and (item[value] is not None) else ";"
                                self.options["csv_files"]["network"].write("{0}\n".format(line[:-1]))

                            # TODO: Should we only add the host or host:port information?
                            traffic_objects.append(item["destination_ip"])

                if "http_conversations" in data:
                    traffic = data["http_conversations"]
                    for item in traffic:
                        if item["url"] not in traffic_objects:
                            self.auxiliary.log("{0}{1:27} {2}".format(" " * 2, "[URL]", item["url"].replace("http", "hxxp")), level = verbose_level)

                            if self.options["csv"]:
                                line = ""
                                for value in ["sha256", "md5", "sha1", "vhash", "size", "type_tag"]:
                                    line += "{0};".format(getattr(sample, value)) if value in dir(sample) else ";"
                                for value in ["destination_ip", "destination_port", "url"]:
                                    line += "{0};".format(item[value]) if (value in item) and (item[value] is not None) else ";"
                                self.options["csv_files"]["network"].write("{0}\n".format(line[:-1]))

                            traffic_objects.append(item["url"])

            if len(traffic_objects) > 0: self.options["auxiliary"].log("", level = verbose_level)
               

