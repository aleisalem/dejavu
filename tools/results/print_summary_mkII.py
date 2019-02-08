#!/usr/bin/python

import glob
import sys
import argparse
from dejavu.utils.graphics import *

def defineArguments():
    parser = argparse.ArgumentParser(prog="print_summary_mkII.py", description="Prints a summary of the achieved results stored in files that match a pattern (e.g., Dejavu_results_*_vt1*).")
    parser.add_argument("-p", "--pattern", help="The pattern to adopt in retrieving files", required=True)
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Long story short(er)...")

        # 2. Retrieve files
        files = glob.glob("Dejavu_results_%s.txt" % arguments.pattern)
        if len(files) < 1:
            prettyPrint("Could not retrieve files with the pattern \"Dejavu_results_%s.txt\"" % (arguments.pattern), "warning")
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
                
        prettyPrint("Results for files of pattern \"Dejavu_results_%s.txt\"" % arguments.pattern, "output")
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
