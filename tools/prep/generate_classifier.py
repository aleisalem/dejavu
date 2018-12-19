#!/usr/bin/python

from dejavu.utils.graphics import *
from dejavu.utils.data import *
from dejavu.learning.scikit_learners import *
import pickle
import argparse, os, glob, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="generate_classifier.py", description="Trains classifiers using some datasets and stores them")
    parser.add_argument("-x", "--malwaredir", help="The directory containing the malicious traces", required=True)
    parser.add_argument("-g", "--goodwaredir", help="The directory containing the benign traces", required=True)
    parser.add_argument("-n", "--clfname", help="The name of the classifier to store", required=True)
    parser.add_argument("-s", "--selectkbest", help="The number of the best features to select prior to training", default=0, type=int, required=False)
    parser.add_argument("-t", "--featuretype", help="The type of features to load", default="static", choices=["static", "dynamic"], required=False)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Alors...")

        # 1. Retrieve the feature vectors
        malware = glob.glob("%s/*.%s" % (arguments.malwaredir, arguments.featuretype))
        goodware = glob.glob("%s/*.%s" % (arguments.goodwaredir, arguments.featuretype))
        
        if len(malware) < 1 or len(goodware) < 1:
            prettyPrint("Could not find feature files under the supplied directories. Exiting", "error")
            return False

        prettyPrint("Successfully retrieved %s malicious features files and %s benign feature files" % (len(malware), len(goodware)))
        # 1.1. Load feature vectors
        X, y = [], []
        for f in malware+goodware:
            x = loadNumericalFeatures(f)
            if len(x) < 1:
                prettyPrint("Empty feature vector found for \"%s\". Skipping" % f, "warning")
                continue
            X.append(x)
            if f in malware:
                y.append(1)
            else:
                y.append(0)

        prettyPrint("Successfully loaded %s %s feature vectors" % (len(X), arguments.featuretype)) 
        # 2. Train classifier
        prettyPrint("Training an ensemble classifier") 
        K = [10, 25, 50, 100, 250]
        E = [10, 25, 50, 75, 100]
        allCs = ["KNN-%s" % k for k in K] + ["FOREST-%s" % e for e in E] + ["SVM"]
        clf, predicted, predicted_test = predictAndTestEnsemble(X, y, classifiers=allCs, selectKBest=int(arguments.selectkbest)) 

        # 3. Save classifier
        clfFile = "%s_%s_ensemble.txt" % (arguments.clfname, arguments.featuretype)
        prettyPrint("Saving classifier to \"%s\"" % clfFile)
        open(clfFile, "w").write(pickle.dumps(clf))

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
