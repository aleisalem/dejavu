#!/usr/bin/python

from dejavu.conf.config import *
from dejavu.utils.graphics import *
from dejavu.utils.apkid import *
from dejavu.learning.feature_extraction import *
from dejavu.learning.scikit_learners import *
import pickle
import argparse, os, glob, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="nwo_tool.py", description="Implements the hybrid process to detect repackaged malware")
    parser.add_argument("-x", "--inputdir", help="The directory containing the APKs", required=True)
    parser.add_argument("-c", "--classifier", help="The path to the classifier trained using AMD+Gplay traces", required=False, default="ensemble.txt")
    parser.add_argument("-d", "--dbdir", help="The directory containing the analysis of APK used for matching", required=True)
    parser.add_argument("-f", "--featuretype", help="The type of features to consider", required=False, default="static", choices=["static", "dynamic"])
    parser.add_argument("-e", "--matchingdepth", help="The rigorosity of app matching", type=int, required=False, default=1, choices=[1,2,3,4])
    parser.add_argument("-t", "--matchingthreshold", help="The percentage beyond which apps are considered similar", type=float, required=False, default=0.5)
    parser.add_argument("-m", "--matchingmethod", help="The matching method to adopt", required=False, default="homemade", choices=["homemade", "simidroid"])
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Alors...")

        # 1. Retrieve the apps to be tested and load their feature vectors
        testAPKs = glob.glob("%s/*.apk" % arguments.inputdir)

        if len(testAPKs) < 1:
            prettyPrint("Could not find any APKs to classify. Exiting", "error")
            return False

        prettyPrint("Successfully retrieved %s malicious features files and %s benign feature files" % (len(testAPKs)))

        prettyPrint("Loading the classifier under \"%s\"" % arguments.classifier)
        clf = pickle.loads(open(arguments.classifier).read())

        # Iterate over test APK's and classify them
        y, predicted = [], []
        matched, classified = 0.0, 0.0
        labels = ["Goodware", "Malware"]
        for app in testAPKs:
            prettyPrint("Processing app \"%s\"" % app)
            originalLabel = 1 if app.find("malware") != -1 else 0
            # See whether we can match this app to any benign app
            useSimiDroid = True if arguments.matchingmethod == "simidroid" else False
            prettyPrint("Matching ...")
            matchings = matchAPKs(app, arguments.dbdir, matchingDepth=arguments.matchingdepth, matchingThreshold=arguments.matchingthreshold, useSimiDroid=useSimiDroid)
            if len(matchings) > 0:
                prettyPrint("The app has been matched with %s apps: %s" % (len(matchings), matchings))
                # Use APKiD to fingerprint the app's compiler
                results = scan(app, 60, "")
                if len(results) < 1:
                    prettyPrint("Could not fingerprint the app's compiler. Skipping", "warning")
                    continue
                try:
                    compiler = results["files"][0]["results"]["compiler"][0]
                except Exception as e:
                    prettyPrint("Could not retrieve compiler from result: %s. Skipping" % str(results), "warning")
                    continue
                
                predictedLabel = 1 if compiler.find("dx") != -1 or compiler.find("dexmerge") != -1 else 0

            else:
                # Load feature vector of app
                featuresFile = app.replace(".apk", ".%s" % arguments.featuretype)
                if os.path.exists(featuresFile):
                    x_test = loadNumericalFeatures(featuresFile)
                else:
                    prettyPrint("Could not locate %s features file for app \"%s\". Skipping" % (arguments.featurestype, app), "warning")
                # Test using misclassified apps
                predictedLabel = clfAMD.predict(x_test)

            # Append results to lists
            y.append(originalLabel)
            predicted.append(predictedLabel)

            prettyPrint("%s app \"%s\" classified as %s" % (labels[originalLabel], app[app.rfind('/')+1:], labels[predictedLabel]))
  
        metrics_all = calculateMetrics(y, predicted)
        prettyPrint("Accuracy: %s" % metrics_all["accuracy"], "out")
        prettyPrint("Precision: %s" % metrics_all["precision"], "out")
        prettyPrint("Recall: %s" % metrics_all["recall"], "out")
        prettyPrint("Specificity: %s" % metrics_all["specificity"], "out")
        prettyPrint("F1 Score: %s" % metrics_all["f1score"], "out")

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
