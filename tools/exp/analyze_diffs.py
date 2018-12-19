#!/usr/bin/python

from dejavu.utils.graphics import *
from dejavu.utils.data import *
from dejavu.conf.config import *
import pickle
import argparse, os, glob, random, requests

safeRating = "The latest tests indicate that this URL contains no malicious software and shows no signs of phishing."
dangerousRating = "The latest tests indicate that this URL contains malicious software or phishing."
suspiciousRating = "This URL has been compromised before, or has some association with spam email messages."
untestedRating = "Because you were curious about this URL, Trend Micro will now check it for the first time. Thanks for mentioning it!"



def defineArguments():
    parser = argparse.ArgumentParser(prog="analyze_diffs.py", description="Retrieves the differences between benign apps [VT==0] and malicious ones [VT>=50%] and analyzes them and their URLs")
    parser.add_argument("-i", "--indirs", help="A list of directories containing the APKs", required=True, nargs='+')
    parser.add_argument("-n", "--experimentname", help="A label to give to the experiment", required=True)
    parser.add_argument("-u", "--analyzeurls", help="Whether to analyze the URL's contacted by the remaining apps", required=False, choices=["yes", "no"], default="yes")
    parser.add_argument("-s", "--saveresults", help="Whether to save the analysis results", required=False, choices=["yes", "no"], default="no")
    parser.add_argument("-l", "--labeling", help="The labeling scheme to adopt in deeming apps as malicious and benign apps", default="vt50p-vt1", choices=["vt10-vt1", "vt50p-vt10", "vt50p-vt1"], required=False)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Vamos!")

        # 1. Retrieve the APK archives
        allApps = []
        for directory in arguments.indirs:
            prettyPrint("Retrieving APKs features from \"%s\"" % directory, "debug")
            allApps += glob.glob("%s/*.apk" % directory)

        if len(allApps) < 1:
            prettyPrint("Could not find APK archives under the supplied directories. Exiting", "error")
            return False

        prettyPrint("Successfully retrieved %s APK archives" % (len(allApps)))
        # 2. Include APK's that comply with the labeling scheme
        differences = []
        analysis = {}
        for app in allApps:
            # Decide upon the feature vector's class according to [arguments.labeling]
            if not os.path.exists("%s/%s" % (VT_REPORTS_DIR, app[app.rfind("/")+1:].replace(".apk", ".report"))):
                prettyPrint("Could not retrieve a VirusTotal report \"%s/%s\". Skipping" % (VT_REPORTS_DIR, app[app.rfind("/")+1:].replace(".apk", ".report")), "warning")
            else:
                # Now decide upon its label
                vtReport = eval(open("%s/%s" % (VT_REPORTS_DIR, app[app.rfind("/")+1:].replace(".apk", ".report"))).read())
                if not "positives" in vtReport.keys():
                    print vtReport.keys()
                    print app
                    prettyPrint("No trace of the \"positives\" field necessary for labeling. Skipping", "warning")
                    continue
                # Check labeling scheme
                if arguments.labeling == "vt10-vt1":
                    if vtReport["positives"] >= 1 and vtReport["positives"] < 10:
                        differences.append((app, vtReport))
                elif arguments.labeling == "vt50p-vt10":
                    if vtReport["positives"] >= 10 and vtReport["positives"]/float(vtReport["total"]) < 0.50:
                        differences.append((app, vtReport))
                elif arguments.labeling == "vt50p-vt1":
                    if vtReport["positives"] >= 1 and vtReport["positives"]/float(vtReport["total"]) < 0.50:
                        differences.append((app, vtReport))
               
        prettyPrint("Differences: %s apps out of %s" % (len(differences), len(allApps)))
        analysis["summary"] = {}
        analysis["summary"]["differences"] = round(len(differences)/float(len(allApps)), 2)
        #analysis["apps"] = differences
        analysis["urls"] = []
 
        # 3. Gather data about the types of apps in differences
        prettyPrint("Analyzing the difference apps")
        # 3.1. Load and parse the encyclopedia malicia
        prettyPrint("Loading the encyclopedia", "debug")
        # 'sha256,sha1,md5,dex_date,apk_size,pkg_name,vercode,vt_detection,vt_scan_date,dex_size,markets,name,types,multiple_names,multiple_types'
        encyclopedia = open("%s/encyclopedia_malicia.csv" % LOOKUP_STRUCTS).read().split('\n')[:-1]
        E = {}
        for enc in encyclopedia:
            line = enc.split(",")
            E[line[0].lower()] = line
        del(encyclopedia) # Save some memory
        prettyPrint("Loaded metadata about %s malicious instances" % len(E))
        adware, trojan, spyware, riskware, monitor, others = 0.0, 0.0, 0.0, 0.0, 0.0, 0.0
        positives, totals = [], []
        counter = 0.0
        for app in differences:
            key = app[1]["sha256"]
            # Retrieve the positives and total if applicable
            if "positives" in app[1].keys():
                positives.append(app[1]["positives"])
                totals.append(app[1]["total"])
            # Retrieve the malware name and type
            t, n = "n/a", "n/a"
            try:
                t, n = E[key][-4], E[key][-3]
                counter += 1
                # Update the counters
                if n.lower().find("adware") != -1:
                    adware += 1
                elif n.lower().find("troj") != -1:
                    trojan += 1
                elif n.lower().find("spyware") != -1:
                    spyware += 1
                elif n.lower().find("riskware") != -1:
                    riskware += 1
                elif n.lower().find("monitor") != -1:
                    monitor += 1
                else:
                    others += 1
            except KeyError as ke:
                prettyPrint("Key \"%s\" not found in the encyclopedia" % key, "error")


            # Check the sanity of the contacted URLs
            if arguments.analyzeurls == "yes":
                prettyPrint("Analyzing the domains and URLs contacted by the apps", "debug")
                report = app[1]
                url_data = {"app": app[0], "positives": report["positives"], "total": report["total"], "family": n, "urls": {}}
                urls = ""
                if "additional_info" in report.keys():
                    if "contacted_domains" in report["additional_info"].keys():
                        for domain in report["additional_info"]["contacted_domains"]:
                            urls += "%s/" % domain[:domain.rfind("/")]

                # Do the same for the contacted url if "android-behaviour" is available
                if "additional_info" in report.keys():
                    if "android-behaviour" in report["additional_info"].keys():
                        if "contacted_urls" in report["additional_info"]["android-behaviour"]:
                            for url in report["additional_info"]["android-behaviour"]["contacted_urls"]:
                                urls += "%s/" % url["url"][:url["url"].rfind("/")]

                print urls
                if len(urls) > 1:
                    response = requests.get("http://api.mywot.com/0.4/public_link_json2?hosts=%s&key=%s" % (urls, WOT_API_KEY))
                    print response.text
                    url_data["urls"] = eval(response.text)
                
                print url_data
                analysis["urls"].append(url_data)

        # 4. Add the stats
        analysis["summary"]["positives"] = round(sum(positives)/float(len(positives)), 2)
        analysis["summary"]["totals"] = round(sum(totals)/float(len(totals)), 2)
        analysis["summary"]["adware"] = adware
        analysis["summary"]["adware_pct"] = round(adware/counter, 2)
        analysis["summary"]["trojan"] = trojan
        analysis["summary"]["trojan_pct"] = round(trojan/counter, 2)
        analysis["summary"]["spyware"] = spyware
        analysis["summary"]["spyware_pct"] = round(spyware/counter, 2)
        analysis["summary"]["riskware"] = riskware
        analysis["summary"]["riskware_pct"] = round(riskware/counter, 2)
        analysis["summary"]["monitor"] = monitor
        analysis["summary"]["monitor_pct"] = round(monitor/counter, 2)
        analysis["summary"]["others"] = others
        analysis["summary"]["others_pct"] = round(others/counter, 2)

        # 5. Save clusters files
        prettyPrint("Here are the results", "output", False)
        prettyPrint("--------------------", "output", False)
        for k in analysis["summary"]:
            prettyPrint("\t%s = %s" % (k, analysis["summary"][k]), "output", False)

        if arguments.saveresults == "yes":  
            diffFile = "dejavu_diffs_%s_%s.txt" % (arguments.experimentname, arguments.labeling)
            prettyPrint("Saving differences to \"%s\"" % diffFile)
            open(diffFile, "w").write(str(analysis))

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Todo claro. Adios!")
    return True

if __name__ == "__main__":
    main()
