#!/usr/bin/python

from dejavu.utils.db import *
from dejavu.conf.config import *
from dejavu.utils.graphics import *
from dejavu.learning.feature_extraction import *
from dejavu.learning.scikit_learners import *
from dejavu.learning.hmm_learner import *
import pickle
import argparse, os, glob, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="nwo_tool.py", description="Implements the hybrid process to detect repackaged malware")
    parser.add_argument("-x", "--malwaredir", help="The directory containing the piggybacked feature vectors/traces", required=True)
    parser.add_argument("-g", "--goodwaredir", help="The directory containing the original feature vectors/traces", required=True)
    parser.add_argument("-m", "--method", help="The method to apply for the detection of misclassified piggybacking data", required=False, choices=["test:AMD+GPlay", "mix:AMD+GPlay", "HMM"], default="test:AMD+GPlay")
    parser.add_argument("-c", "--classifier", help="The path to the classifier trained using AMD+Gplay traces", required=False, default="ensemble.txt")
    parser.add_argument("-t", "--featuretype", help="The type of features used to load", required=False, default="static", choices=["static", "dynamic"])
#    parser.add_argument("-f", "--fileextension", help="The extension of the trace files", required=False, default="log")
#    parser.add_argument("-i" , "--includeargs", help="Whether to include arguments in the parsed traces", required=False, default="no", choices=["yes", "no"])
#    parser.add_argument("-c", "--localization", help="The method used to localize malicious behaviors", required=False, default="binary", choices=["binary", "window", "n-ary"])
#    parser.add_argument("-w", "--windowsize", help="The size of the window to consider with the \"window\" localization method", required=False, default=3, type=int)
#    parser.add_argument("-s", "--splitsize", help="The value of (n) upon considering the \"n-ary\" split localization method", required=False, default=3, type=int)
#    parser.add_argument("-t", "--tau", help="The threshold log likelihood value to consider for HMM classification", required=False, type=float, default=0.0)
#    parser.add_argument("-l", "--lambd", help="The maximum length to consider per trace", required=False, type=int, default=0)
#    parser.add_argument("-o", "--storeresults", help="Whether to store results in the database", required=False, default="no", choices=["yes", "no"])
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Alors...")

        # 1. Retrieve the piggybacked and original traces
        malAPKs = glob.glob("%s/*.%s" % (arguments.malwaredir, arguments.featuretype))
        goodAPKs = glob.glob("%s/*.%s" % (arguments.goodwaredir, arguments.featuretype))

        if len(malAPKs) < 1 or len(goodAPKs) < 1:
            prettyPrint("Could not find feature files under the supplied directories. Exiting", "error")
            return False

        prettyPrint("Successfully retrieved %s malicious features files and %s benign feature files" % (len(malAPKs), len(goodAPKs)))
        # 1.1. Load feature vectors
        X, y = [], []
        allAPKs = [] + malAPKs + goodAPKs
        #for i in range(10):
        #    prettyPrint("Shuffling %s" % i)
        #    random.shuffle(allAPKs)

        for f in allAPKs:
            x = loadNumericalFeatures(f)
            if len(x) < 1:
                prettyPrint("Empty feature vector found for \"%s\". Skipping" % f, "warning")
                continue
            X.append(x)
            if f in malAPKs:
                y.append(1)
            else:
                y.append(0)

        # 2. Split into training and test feature vectors
        max_test = float(len(X))*0.33
        X_train, X_test, y_train, y_test = [] + X, [], [] + y, []
        while len(X_test) < max_test:
            index = random.randint(0, len(X_train)-1)
            X_test.append(X_train.pop(index))
            y_test.append(y_train.pop(index))

        prettyPrint("Successfully retrieved %s training feature vectors and %s test feature vectors" % (len(X_train), len(X_test)))

        # 3. Train a  classifier + validate
        prettyPrint("Training an ensemble classifier")
        K = [10, 25, 50, 100, 250]
        E = [10, 25, 50, 75, 100]
        allCs = ["KNN-%s" % k for k in K] + ["FOREST-%s" % e for e in E] + ["SVM"]
        clf, predicted, predicted_test = predictAndTestEnsemble(X_train, y_train, X_test, y_test, classifiers=allCs)#, selectKBest=int(arguments.selectkbest))

        prettyPrint(calculateMetrics(y_test, predicted_test), "out")

        # 4. Retrieve the misclassified feature vectors
        X_misclassified, y_misclassified = [], []
        for index in range(len(y_test)):
            if y_test[index] != predicted_test[index]:
                X_misclassified.append(X_test[index])
                y_misclassified.append(y_test[index])

        prettyPrint("Retrieved %s misclassified test vectors out of %s" % (len(X_misclassified), len(X_test)))

        if arguments.method == "test:AMD+GPlay":
            # 5. Load the AMD+Gplay classifier
            prettyPrint("Loading the classifier under \"%s\"" % arguments.classifier)
            clfAMD = pickle.loads(open(arguments.classifier).read())

            # 6. Test using misclassified apps
            predicted_all = clfAMD.predict(X_test)
            metrics_all = calculateMetrics(y_test, predicted_all)
            predicted_misclassified = clfAMD.predict(X_misclassified)
            metrics_mis = calculateMetrics(y_misclassified, predicted_misclassified)
        
            prettyPrint("Accuracy (all): %s versus accuracy (misclassified): %s" % (metrics_all["accuracy"], metrics_mis["accuracy"]), "out")
            prettyPrint("Specificity (all): %s versus specificity (misclassified): %s" % (metrics_all["specificity"], metrics_mis["specificity"]), "out")
            prettyPrint("F-score (all): %s versus F-score (misclassified): %s" % (metrics_all["f1score"], metrics_mis["f1score"]), "out")

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
