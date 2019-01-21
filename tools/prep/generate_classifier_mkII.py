#!/usr/bin/python

from dejavu.utils.graphics import *
from dejavu.utils.data import *
from dejavu.conf.config import *
from dejavu.learning.scikit_learners import *
import pickle
import argparse, os, glob, random
from sklearn.naive_bayes import MultinomialNB

def defineArguments():
    parser = argparse.ArgumentParser(prog="generate_classifier.py", description="Trains classifiers using some datasets and stores them")
    parser.add_argument("-i", "--indirs", help="A list of directories containing the feature vectors (malicious and benign)", required=True, nargs='+')
    parser.add_argument("-a", "--dirlabels", help="A description of the dataset dirs (i.e., malicious or benign)", required=False, nargs='+', choices=["malicious", "benign"], default=[])
    parser.add_argument("-n", "--clfname", help="The name of the classifier to store", required=True)
    parser.add_argument("-c", "--clftype", help="The type of the classifier to generate", required=False, default="ensemble", choices=["ensemble", "naivebayes"])
    parser.add_argument("-s", "--selectkbest", help="The number of the best features to select prior to training", default=0, type=int, required=False)
    parser.add_argument("-t", "--featuretype", help="The type of features to load", default="static", choices=["static", "dynamic"], required=False)
    parser.add_argument("-l", "--labeling", help="The labeling scheme to adopt", default="vt1-vt1", choices=["old", "vt1-vt1", "vt50p-vt50p", "vt50p-vt1"], required=False)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Alors...")

        # 1. Retrieve the feature vectors
        allApps = []
        for directory in arguments.indirs:
            prettyPrint("Retrieving \"%s\" features from \"%s\"" % (arguments.featuretype, directory), "debug")
            allApps += glob.glob("%s/*.%s" % (directory, arguments.featuretype))

        if len(allApps) < 1:
            prettyPrint("Could not find feature files under the supplied directories. Exiting", "error")
            return False

        prettyPrint("Successfully retrieved %s feature files" % (len(allApps)))
        # 1.1. Load feature vectors
        X, y = [], []
        for f in allApps:
            label = -1
            x = loadNumericalFeatures(f)
            if len(x) < 1:
                prettyPrint("Empty feature vector found for \"%s\". Skipping" % f, "warning")
                continue


            if arguments.labeling == "old":
                if len(arguments.dirlabels) != len(arguments.indirs):
                    prettyPrint("The dimensionality of the input directories and their descriptions is different", "error")
                    return False

                for index in range(len(arguments.dirlabels)):
                    if f.find(arguments.indirs[index]) != -1:
                        label = 1 if arguments.dirlabels[index] == "malicious" else 0
                    
                prettyPrint("App \"%s\" deemed %s" % (f, ["benign", "malicious", "unknown"][label]), ["debug", "error", "warning"][label])
             

            # Decide upon the feature vector's class according to [arguments.labeling]
            else:
                if os.path.exists("%s/%s" % (VT_REPORTS_DIR, f[f.rfind("/")+1:].replace(".%s" % arguments.featuretype, ".report"))):
                    prettyPrint("Could not retrieve a VirusTotal report \"%s/%s\". Skipping" % (VT_REPORTS_DIR, f[f.rfind("/")+1:].replace(".%s" % arguments.featuretype, ".report")), "warning")
                    # Now decide upon its label
                    vtReport = eval(open("%s/%s" % (VT_REPORTS_DIR, f[f.rfind("/")+1:].replace(".%s" % arguments.featuretype, ".report"))).read())
                    if not "positives" in vtReport.keys():
                        prettyPrint("No trace of the \"positives\" field necessary for labeling. Skipping", "warning")
                        continue
 
                    if arguments.labeling == "vt1-vt1":
                         label = 1 if vtReport["positives"] >= 1 else 0

                    elif arguments.labeling == "vt50p-vt50p":
                        label = 1 if vtReport["positives"]/float(vtReport["total"]) >= 0.50 else 0

                    else:
                        # Malicious if VT >= 50%, benign if VT == 0
                        if vtReport["positives"]/float(vtReport["total"]) >= 0.50:
                            label = 1
                        else:
                            if vtReport["positives"] < 1:
                                label = 0
                
                    prettyPrint("App \"%s\" with %s positives out of %s scans deemed %s" % (f, vtReport["positives"], vtReport["total"], ["benign", "malicious", "unknown"][label]), ["debug", "error", "warning"][label])


            # Make sure to add AMD feature vectors only
            if label == 1 and f.lower().find("amd") != -1:
                X.append(x)
                y.append(1)
            else:
                if label == 0:
                    X.append(x)
                    y.append(0)

        prettyPrint("Successfully loaded %s %s feature vectors: %s malicious and %s benign" % (len(X), arguments.featuretype, sum(y), len(y)-sum(y))) 

        # 2. Train classifier
        print len(X), len(y)
        if arguments.clftype == "naivebayes":
            prettyPrint("Training a Multinomial naive Bayes classifier")
            clf = MultinomialNB()
            clf.fit(X, y)
        elif arguments.clftype == "ensemble":
            prettyPrint("Training an ensemble classifier") 
            K = [10, 25, 50, 100, 250]
            E = [10, 25, 50, 75, 100]
            allCs = ["KNN-%s" % k for k in K] + ["FOREST-%s" % e for e in E] + ["SVM"]
            clf, predicted, predicted_test = predictAndTestEnsemble(X, y, classifiers=allCs, selectKBest=int(arguments.selectkbest)) 

        # 3. Save classifier
        clfFile = "%s_%s_%s_%s.txt" % (arguments.clfname, arguments.clftype, arguments.featuretype, arguments.labeling.replace("-", "_"))
        prettyPrint("Saving classifier to \"%s\"" % clfFile)
        open(clfFile, "w").write(pickle.dumps(clf))

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
