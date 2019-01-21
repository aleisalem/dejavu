#!/usr/bin/python

from dejavu.utils.graphics import *
from dejavu.utils.data import *
from dejavu.conf.config import *
from dejavu.learning.scikit_learners import *
import pickle
import argparse, os, glob, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="generate_clusters.py", description="Build clusters of package names used during experiments")
    parser.add_argument("-i", "--indirs", help="A list of directories containing the APKs", required=True, nargs='+')
    parser.add_argument("-n", "--clsname", help="The name of the file containing the clusters", required=True)
    parser.add_argument("-l", "--labeling", help="The labeling scheme to adopt in choosing the benign apps", default="vt1", choices=["old", "vt1", "vt10p", "vt50p"], required=False)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Andiamo...")

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
        benignApps, packageNames = [], []
        packageToHash = {}
        for app in allApps:
            # Decide upon the feature vector's class according to [arguments.labeling]
            if arguments.labeling == "old":
                # Rely on the original labeling of the dataset's authors
                benignApps.append(app)

            else:
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
                    elif arguments.labeling == "vt1" and vtReport["positives"] < 1:
                        benignApps.append(app)
                    elif arguments.labeling == "vt10" and vtReport["positives"] < 10:
                        benignApps.append(app)
                    elif arguments.labeling == "vt50p" and vtReport["positives"]/float(vtReport["total"]) < 0.50:
                        benignApps.append(app)
               
        prettyPrint("Number of APK's to consider for clustering is %s" % len(benignApps), "debug")
 
        # 3. Extract package names
        for app in benignApps:
            prettyPrint("Extracting package name from \"%s\"" % app, "debug")
            packageName = getPackageNameFromAPK(app)
            if len(packageName) > 0:
                packageNames.append(packageName)
                packageToHash[packageName] = app[app.rfind("/")+1:].replace(".apk", "").lower()
 
        # 4. Cluster package names
        prettyPrint("Clustering %s package names" % len(packageNames))
        clusters = clusterStrings(packageNames)

        # 5. Save clusters files
        clsFile = "dejavu_clusters_%s_%s.txt" % (arguments.clsname, arguments.labeling)
        pkgFile = "dejavu_pkgToHash_%s_%s.txt" % (arguments.clsname, arguments.labeling)
        prettyPrint("Saving package name clusters to \"%s\" and package-to-hash file to \"%s\"" % (clsFile, pkgFile))
        open(clsFile, "w").write(str(clusters))
        open(pkgFile, "w").write(str(packageToHash))

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Ciao ;)")
    return True

if __name__ == "__main__":
    main()
