#!/usr/bin/python

from dejavu.utils.db import *
from dejavu.conf.config import *
from dejavu.utils.graphics import *
from dejavu.learning.feature_extraction import *
from dejavu.learning.scikit_learners import *
import pickle
import argparse, os, glob, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="nwo_tool.py", description="Implements the hybrid process to detect repackaged malware")
    parser.add_argument("-x", "--inputdir", help="The directory containing the APKs", required=True)
    parser.add_argument("-c", "--classifier", help="The path to the classifier trained using AMD+Gplay traces", required=False, default="ensemble.txt")
    parser.add_argument("-d", "--dbdir", help="The directory containing the analysis of APK used for matching", required=True)
    parser.add_argument("-e", "--matchingdepth", help="The rigorosity of app matching", type=int, required=False, default=1, choices=[1,2,3,4])
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

        # TODO: Compare and match APK if possible
        

        prettyPrint("Loading the classifier under \"%s\"" % arguments.classifier)
        clf = pickle.loads(open(arguments.classifier).read())

        # Test using misclassified apps
        predicted_all = clfAMD.predict(X_test)
        metrics_all = calculateMetrics(y_test, predicted_all)
        #prettyPrint("Accuracy (all): %s versus accuracy (misclassified): %s" % (metrics_all["accuracy"], metrics_mis["accuracy"]), "out")

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
