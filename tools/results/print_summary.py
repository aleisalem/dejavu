#!/usr/bin/python

import glob
import sys
import argparse
from dejavu.utils.graphics import *

def defineArguments():
    parser = argparse.ArgumentParser(prog="bake_pies.py", description="Plots the distribution of matching techniques that correctly classified APKs in a dataset as a pie chart")
    parser.add_argument("-i", "--dataset", help="The experiment label given to files (e.g., Piggybacked, Original, Malgenome, etc.)", required=True)
    parser.add_argument("-l", "--labeling", help="The labeling scheme adopted during the experiments", required=True, choices=["vt1-vt1", "vt50p-vt50p", "vt50p-vt1"])
    parser.add_argument("-d", "--depth", help="The matching depth adopted during the experiments", required=False, default="all")
    parser.add_argument("-t", "--thresholds", help="The matching and classification thresholds adopted during the experiments", required=False, default="all")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Long story short(er)...")

        # 2. Retrieve files
        depth = "*" if arguments.depth == "all" else arguments.depth
        thresholds = "*" if arguments.thresholds == "all" else arguments.thresholds
        files = glob.glob("Dejavu_results_%s_%s_%s_%s.txt" % (arguments.dataset, arguments.labeling, depth, thresholds))
        if len(files) < 1:
            prettyPrint("Could not retrieve files with the pattern \"Dejavu_results_%s_*_%s_%s_%s.txt\"" % (arguments.dataset, arguments.labeling, arguments.depth, arguments.thresholds), "warning")
            return False

        prettyPrint("Successfully retrieved %s data files" % len(files))
    
        # 3. Parse data files and collect data
        files.sort()
        performance = {"total": [], "times": [], "accuracies": [], "false": [], "quick_matching": [], "classification": [], "deep_matching": []}
        for f in files:
            prettyPrint("Processing data in \"%s\"" % f)
            data = eval(open(f).read())
            performance["total"].append(len(data))
            correct = 0.0
            quick, deep, clf = 0.0, 0.0, 0.0
            for k in data:
                datapoint = data[k]
                performance["times"].append(datapoint[2])
                if datapoint[3] == datapoint[4]:
                    correct += 1.0
                    if datapoint[6] == "quick_matching":
                        quick += 1.0
                    elif datapoint[6] == "classification":
                        clf += 1.0
                    else:
                        deep += 1.0

            # Accuracy
            performance["accuracies"].append(correct/float(len(data)))
            performance["false"].append((float(len(data))-correct)/float(len(data)))
            performance["quick_matching"].append(quick/float(len(data)))
            performance["classification"].append(clf/float(len(data)))
            performance["deep_matching"].append(deep/float(len(data)))

        total = sum(performance["total"])/float(len(performance["total"]))
        time = sum(performance["times"])/float(len(performance["times"]))
        accuracy = sum(performance["accuracies"])/float(len(performance["accuracies"]))
        false = sum(performance["false"])/float(len(performance["false"]))
        quick = sum(performance["quick_matching"])/float(len(performance["quick_matching"]))
        clf = sum(performance["classification"])/float(len(performance["classification"]))
        deep = sum(performance["deep_matching"])/float(len(performance["deep_matching"]))
                
        prettyPrint("Dataset: %s, labeling scheme: %s, thresholds: %s, depth: %s" % (arguments.dataset, arguments.labeling, arguments.thresholds, arguments.depth), "output")
        prettyPrint("Average total: %s" % total, "output")
        prettyPrint("Average Accuracy: %s" % accuracy, "output")
        prettyPrint("Average False (P/N): %s" % false, "output")
        prettyPrint("Average time (in seconds): %s" % time, "output")
        prettyPrint("Avg. quick: %s, avg. classification: %s, avg. deep: %s" % (quick, clf, deep), "output")

    except Exception as e:
        prettyPrintError(e)
        return False

    prettyPrint("That's all she wrote!")
    return True
        

if __name__ == "__main__":
    main()
