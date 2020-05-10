# VTISearch - VirusTotal Intelligence Search

*VTISearch* is a small utility for running a VirusTotal Intelligence search query. A query can include powerful search modifiers (listed in the [documentation](https://support.virustotal.com/hc/en-us/articles/360001385897-File-search-modifiers)) that permit efficient threat research and hunting operations.

The program leverages v3 of the VirusTotal API. Please note that for some features (including Intelligence Search), you need a private API key. The API key is requested upon the first start and saved to the keyring of the system for security reasons.

By default, *VTISearch* retrieves information about the first 20 samples that are associated with the search query. However, results for up to 300 samples can be requested as well with the help of the `-l` (`--limit`) parameter.

Information includes the list of sample hashes (MD5, SHA1, SHA256, and - if existing - the VirusTotal *vhash* similarity hash), the type and size of the artifact, dates of (first and last) submission, and also detection statistics.

Additional details, e.g., scanning results per vendor, can be displayed when speciying the verbose (`-v`) parameter. Up to three different verbosity levels are supported.

*VTISearch* is capable of downloading the samples as well as behavioral (dynamic analysis) reports for an Intelligence search. Dynamic analysis reports are also automatically parsed in order to extract network-based Indicators of Compromise (IOCs). 

When using the `--csv` option, results can be exported in CSV format for subsequent import in, e.g., *Maltego* or other graph visualization programs.


## Features

* Retrieves information for up to 300 artifacts that are related to the search query.
* Information includes meta data as well as detailed scanning and detection results upon request.
* Supports the automatic download of associated samples and behavioral (dynamic analysis) reports.
* Behavioral reports are automatically scanned for network-based Indicators of Compromise (IOCs).
* Use of multiple workers to speed up operations.\*
* All information is categorized in different sub-folders. Detailed logs facilitate post-processing.
* Results can be exported in CSV format for subsequent relationship visualization with, e.g., Maltego.

(\* Behavior report parsing is still mostly sequential and needs to be updated.)


## Requirements 

* Linux operating system (tested on Ubuntu 18.04)

* Python 3.7+  
* vt
* keyring

All required packages can be comfortably installed via pip:

```bash
$ pip3 install vt keyring 
```


## Options and Usage

```
usage: vti_search.py [-h] [-q QUERY] [-l LIMIT] [--logfile LOG]
                     [--download-dir DOWNLOAD_DIR] [-d] [-f SAMPLE_FILE]
                     [--no-behavior] [-v] [--csv]

optional arguments:
  -h, --help                          Show this help message and exit

  -q QUERY, --query QUERY             Run a VirusTotal Intelligence search query.

  -l LIMIT, --limit LIMIT             Limits the number of samples to return.

  --logfile LOG                       Name of the log file.

  --download-dir DOWNLOAD_DIR         Name of the directory where retrieved information will
                                      be stored in.

  -d, --download                      If set, also downloads samples from VirusTotal that
                                      are referenced in an Intelligence search.

  -f SAMPLE_FILE, --file SAMPLE_FILE  Downloads samples that are referenced in a file.

  --no-behavior                       If set, does not download behavior reports for
                                      samples.

  -v, --verbose                       If set, display verbose information about reports. Use
                                      -vvv to see detailed scan results.

  -w, --workers WORKERS               Number of concurrent workers.

  --csv                               If set, display results as comma-separated values.
```

In the majority of cases, *VTISearch* will be executed with the `-q` (`--query`) parameter. This query is sent to VirusTotal via the `v3` API. Respective samples will not be downloaded by default. However, this procedure can be easily activated with the `-d` parameter.

```bash
$ python3 vti_search.py -q "evil.exe" -d
```

Rather than performing an Intelligence search, it is also possible processing a list of hashes that are stored in a file. As such, the program can be used as a quick sample downloader and IOC processor:

```bash
$ python3 python3 vti_search.py -f ./iocs.txt
```

The approaches can also be mixed. For instance, you might want to first check the results of a query slightly more in detail, adapt the list of samples in scope, and then re-run the program with the download option enabled for the updated sample list.

Alternatively, you might want to combine the results of an Intelligence search with indicators highlighted in a (third-party) report in order to create a more detailed overview of a specific campaign or operation.

By default, all log files, samples, and reports are stored in a separate directory (identified by its timestamp) that is created at program startup in the `downloads` folder. If you prefer rather updating an existing directory, you can explicitly set the `--download-dir` parameter.

For instance, assuming you would like to investigate an APT campaign, you can perform an Intelligence search, retrieve the first 100 results in detailed format, and store all information in a specific folder as follows:

```bash
$ python3 vt_search.py -d -q <query> -l 100 -vvv --download-dir=downloads/apt
```

## Sample Queries and Intelligence Searches

The following queries are solely for demonstration purposes to illustrate search capabilities and possible use cases for the program:

1. Show samples with detection statistics that were submitted after May 1, 2020 and were detected by more than five but less than 10 vendors. 

```bash
$ python3 vti_search.py -q "ls:2020-05-01+ positives:5+ positives:10-" -v --no-behavior
```


2. Show PDF documents in German that were delivered as an email attachment and contain an embedded JavaScript.

```
$ python3 vti_search.py -q "tag:attachment type:pdf lang:german tag:js-embedded"
```


3. Show signed executables with a size of less than 300KB that were detected by more than five vendors.

```bash
$ python3 vti_search.py -q "size:300KB- positives:5+ tag:signed type:peexe"
```


4. Show up to five samples, representing Microsoft Office documents that execute code upon opening and likely set an AutoRun key for persistence.

```bash
$ python3 vti_search.py -q "behavior:'currentversion\run\' type:docx tag:auto-open" -l 5
```


## Data Export and Collaboration

*VTISearch* supports exporting all information in CSV format. Exported contents are dependent on the verbosity level.

For instance, when specifying the `-vvv` parameter, detailed anti-virus scanning reports will be exported into CSV format. On the other hand, when solely specifying the `-v` parameter, higher level summary statistics will be created.

The list of network indicators retrieved from dynamic analysis sandbox reports can be exported in CSV format as well. This information can subsequently be loaded with, e.g., [Maltego](https://www.maltego.com/) in order to visualize respective relationships.


## Example Run

```bash
$ python3 vti_search.py -d -q evil.exe -l 10 -vv

VTISearch - VirusTotal Intelligence Search - Version 0.1.0

Written by Stefan Voemel.
------------------------------------------------------------------------------------------

2axxxxxxxxxe4b2be454ed0dxxxxxxxxxx7db18e9780xxxxxxxx10dcabxxxxxx
  MD5:                        xxxxx09dxxxxxc271cxxxxx5cb6xxxxx
  Sha1:                       xxxxxx71bxxxxx4aaxxxx383xxxxce8xxxxe00xx
  VHash:                      xxx04xx5xdxx1xx8xxxx2txxxx

  Type:                       PE32 executable for MS Windows (GUI) Intel 80386 32-bit
  Type Tag:                   peexe
  Size:                       73802

  First submission:           2020-05-07 11:16:58
  Last submission:            2020-05-07 11:16:58
  Number of submissions:      1
  Unique sources:             1

  Malicious:                  58
  Suspicious:                 0
  Undetected:                 14

  [Host]                      1xx.16.xxx.xxx:4444

798xxxx29xxxx4xxxe3dxxxa8xfxx3x2excxxxe7xxc4cxxxd4x4fx4x05xxxxxx
  MD5:                        xxxx27xxxx28xxxx14xxxb34xxx13xxx
  Sha1:                       xxxxb6xxx1f4xxxxdb26xxxx94xxxx5dxx61cxxx
  VHash:                      xxx03xxx7dxxx2xx

  Type:                       PE32 executable for MS Windows (console) Intel 80386 32-bit
  Type Tag:                   peexe
  Size:                       4752

  First submission:           2011-07-04 22:00:08
  Last submission:            2020-05-06 13:39:21
  Number of submissions:      1951
  Unique sources:             1472

  Malicious:                  58
  Suspicious:                 0
  Undetected:                 14

  [Host]                      1xx.1xx.221.22:80
  [Host]                      1xx.1xx.131.241:80
  [Host]                      1xx.xxx.78.24:443
  [Host]                      1xx.xxx.78.25:443
  [URL]                       hxxp://www.xxxxxxxx.com/ad.html
```


## File Structure

```bash
├── downloads            Program data
│   └── <timestamp>
│       ├── behavior/    Directory for behavioral reports
│       ├── log.txt      Detailed log file with program runtime messages
│       ├── network.csv  Network indicators
│       ├── reports/     Directory for summary reports and network indicators (*.ioc)
│       ├── samples/     Directory for malware samples
│       ├── samples.txt  List of malware samples in scope
│       └── search.csv   Results of the Intelligence search in CSV format
│   
├── lib                  Program libraries
│   ├── auxiliary.py
│   ├── sandboxes.py
│   └── vt.py
├── README.md
└── vti_search.py        Main program file
```


## Comments and Additional Notes

I am not a professional developer or software engineer, and this program should be seen as a small helper tool. While I do enjoy periodically writing smaller utilities in my free time for Incident Response, malware analysis, and Threat Intelligence scenarios, I very rarely upload any of them. 

The only reason why I did so for this program is, because the number of alternatives for the v3 VirusTotal API is currently still very much limited. This being said, I spend the vast majority of my time (i.e., my professional life) with leading security teams and offering strategic advice and guidance on a higher level. As such, if you believe that the code is *\<beep\>*, you are probably right.
