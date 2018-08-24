#!/usr/bin/python

from dejavu.utils.graphics import *
from dejavu.utils.data import *
from dejavu.learning.scikit_learners import *
import pickle
import argparse, os, glob, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="preliminary_experiments.py", description="Runs preliminary experiments to demonstrate the adversarial setting")
    parser.add_argument("-c", "--clf", help="The path to the classifier to load and use for prediction", required=True)
    parser.add_argument("-d", "--indir", help="The path to the feature vectors to load and use as test dataset", required=True)
    parser.add_argument("-t", "--type", help="The type of feature vectors being loaded", required=False, default="goodware", choices=["malware", "goodware"])
    parser.add_argument("-f", "--fileext", help="The extension of the files containing the feature vectors", required=False, default="static", choices=["static", "dynamic"])
    parser.add_argument("-e", "--expname", help="A label to give to the experiment", default="Preliminary Experiment", required=False)
    parser.add_argument("-s", "--store", help="Whether to store the recorded results", default="no", required=False, choices=["no", "yes"])
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Andiamo!")
 
        # 1. Load the classifier
        prettyPrint("Loading classifier")
        clf = pickle.loads(open(arguments.clf).read())

        # 2. Retrieve the feature vectors
        testData = glob.glob("%s/*.%s" % (arguments.indir, arguments.fileext))
        
        if len(testData) < 1:
            prettyPrint("Could not find feature files under \"%s\". Exiting" % arguments.indir, "error")
            return False

        prettyPrint("Successfully retrieved %s \"%s\"  features files" % (len(testData), arguments.fileext))
        # 2.1. Load feature vectors
        prettyPrint("Loading feature vectors")
        Xtest, ytest = [], []
        for f in testData:
            x = loadNumericalFeatures(f)
            if len(x) < 1:
                prettyPrint("Empty feature vector found for \"%s\". Skipping" % f, "warning")
                continue
            Xtest.append(x)
            if arguments.type == "malware":
                ytest.append(1)
            else:
                ytest.append(0)

        # 3. Predict
        prettyPrint("Predicting")
        predicted = clf.predict(Xtest)
        metrics = calculateMetrics(ytest, predicted)
        # 3.1. Display results
        prettyPrint("Accuracy: %s" % metrics["accuracy"], "output")
        prettyPrint("Recall: %s" % metrics["recall"], "output")
        prettyPrint("Precision: %s" % metrics["precision"], "output")
        prettyPrint("Specificity: %s" % metrics["specificity"], "output")
        prettyPrint("F1 Score: %s" % metrics["f1score"], "output")

        # 4. Store results
        if arguments.store == "yes":
            fileName = "Dejavu_results_%s_%s.txt" % (arguments.expname.replace(" ", "_").lower(), arguments.fileext)
            prettyPrint("Storing results under \"%s\"" % fileName)
            open(fileName, "w").write(str(metrics))

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
