#!/usr/bin/python

from dejavu.utils.graphics import *
from dejavu.utils.data import *
import pickle
import argparse, os, glob, random

def defineArguments():
    parser = argparse.ArgumentParser(prog="results_summary.py", description="Prints a summary of the results stored in the dejavu results file")
    parser.add_argument("-i", "--infile", help="The input results file containing the results data", required=True)
    parser.add_argument("-t", "--type", help="The type of the experiment ran", required=True, choices=["malicious", "benign"])
    parser.add_argument("-r", "--reportsdir", help="The directory containing the VirusTotal reports", required=False, default="./")
    parser.add_argument("-s", "--save", help="Whether to save the summarized data", required=False, default="no", choices=["yes", "no"])
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Right, what do we have here?!")
        # 1. Load data
        data = eval(open(arguments.infile).read())
        # 2. Extract information
        accuracy = 0.0
        correct, incorrect = 0.0, 0.0
        quick, clf, deep = 0.0, 0.0, 0.0
        quick_inc, clf_inc, deep_inc = 0.0, 0.0, 0.0
        dx, dexlib, na = 0.0, 0.0, 0.0
        dx_inc, dexlib_inc, na_inc = 0.0, 0.0, 0.0

        # 2.1. Basic info
        for key in data:
            instance = data[key]
            # Correctly classified?
            if instance[3] == instance[4]:
                correct += 1
                # Which compiler?
                if instance[1].find("dx") != -1:
                    dx += 1
                elif instance[1].find("dexlib") != -1:
                    dexlib += 1
                else:
                    na += 1
                # Which matching technique?
                if instance[-2] == "quick_matching":
                    quick += 1
                elif instance[-2] == "classification":
                    clf += 1
                else:
                    deep += 1
            else:
                incorrect += 1 
                # Which compiler?
                if instance[1].find("dx") != -1:
                    dx_inc += 1
                elif instance[1].find("dexlib") != -1:
                    dexlib_inc += 1
                else:
                    na_inc += 1
                # Which matching technique?
                if instance[-2] == "quick_matching":
                    quick_inc += 1
                elif instance[-2] == "classification":
                    clf_inc += 1
                else:
                    deep_inc += 1
                
        accuracy = correct / len(data)
        total = correct+incorrect
        accuracy_after_vt1 = 0.0
        accuracy_after_vt10 = 0.0
        accuracy_after_vt50p = 0.0
        # 2.2. Updated VirusTotal labels
        if arguments.type == "malicious":
            actually_benign_1 = 0.0
            actually_benign_10 = 0.0
            actually_benign_50p = 0.0
            for d in data:
                instance = data[d]
                if instance[3] != instance[4]:
                    key = d[d.rfind("/")+1:].replace(".apk", "")
                    if os.path.exists("%s/%s.report" % (arguments.reportsdir, key)):
                        report = eval(open("%s/%s.report" % (arguments.reportsdir, key)).read())
                        if "positives" in report.keys() and "total" in report.keys():
                            if report["positives"] < 1:
                                actually_benign_1 += 1.0
                            if report["positives"] < 10:
                                actually_benign_10 += 1.0
                            if report["positives"]/float(report["total"]) < 0.5:
                                actually_benign_50p += 1.0
        else:
            actually_malicious_1 = 0.0
            actually_malicious_10 = 0.0
            actually_malicious_50p = 0.0
            for d in data:
                instance = data[d]
                if instance[3] != instance[4]:
                    key = d[d.rfind("/")+1:].replace(".apk", "")
                    if os.path.exists("%s/%s.report" % (arguments.reportsdir, key)):
                        report = eval(open("%s/%s.report" % (arguments.reportsdir, key)).read())
                        if "positives" in report.keys() and "total" in report.keys():
                            if report["positives"] >= 1:
                                actually_malicious_1 += 1.0
                            if report["positives"] >= 10:
                                actually_malicious_10 += 1.0
                            if report["positives"]/float(report["total"]) >= 0.5:
                                actually_malicious_50p += 1.0
 

        accuracy_after_vt1 = (correct + actually_benign_1) / len(data) if arguments.type == "malicious" else (correct + actually_malicious_1) / len(data)
        accuracy_after_vt10 = (correct + actually_benign_10) / len(data) if arguments.type == "malicious" else (correct + actually_malicious_10) / len(data)
        accuracy_after_vt50p = (correct + actually_benign_50p) / len(data) if arguments.type == "malicious" else (correct + actually_malicious_50p) / len(data)
        
        # 3. Display (and save) data
        results = {}
        results["total"] = len(data)
        # Correctly classified
        results["correct"] = "%s (%s%%)" % (correct, round(correct/total*100.0, 2))
        results["correct_qm"] = "%s (%s%%)" % (quick, round(quick/correct*100.0, 2)) 
        results["correct_clf"] = "%s (%s%%)" % (clf, round(clf/correct*100.0, 2))
        results["correct_deep"] = "%s (%s%%)" % (deep, round(deep/correct*100.0, 2))
        results["correct_dx/dexmerge"] = "%s (%s%%)" % (dx, round(dx/correct*100.0, 2))
        results["correct_dexlib"] = "%s (%s%%)" % (dexlib, round(dexlib/correct*100.0, 2))
        results["correct_na"] = "%s (%s%%)" % (na, round(na/correct*100.0, 2))
        # Incorrectly classified
        results["incorrect"] = "%s (%s%%)" % (incorrect, round(incorrect/total*100.0, 2))
        results["incorrect_qm"] = "%s (%s%%)" % (quick_inc, round(quick_inc/incorrect*100.0, 2)) 
        results["incorrect_clf"] = "%s (%s%%)" % (clf_inc, round(clf_inc/incorrect*100.0, 2))
        results["incorrect_deep"] = "%s (%s%%)" % (deep_inc, round(deep_inc/incorrect*100.0, 2))
        results["incorrect_dx/dexmerge"] = "%s (%s%%)" % (dx_inc, round(dx_inc/incorrect*100.0, 2))
        results["incorrect_dexlib"] = "%s (%s%%)" % (dexlib_inc, round(dexlib_inc/incorrect*100.0, 2))
        results["incorrect_na"] = "%s (%s%%)" % (na_inc, round(na_inc/incorrect*100.0, 2))
        # Updated labels
        if arguments.type == "malicious":
            results["actually_benign_vt1"] = actually_benign_1
            results["accuracy_vt1"] = "%s%%" % round(accuracy_after_vt1*100.0, 2)
            results["actually_benign_vt10"] = actually_benign_10
            results["accuracy_vt10"] = "%s%%" % round(accuracy_after_vt10*100.0, 2)
            results["actually_benign_vt50p"] = actually_benign_50p
            results["accuracy_vt50p"] = "%s%%" % round(accuracy_after_vt50p*100.0, 2)
        else:
            results["actually_malicious_vt1"] = round(actually_malicious_1*100.0, 2)
            results["accuracy_vt1"] = "%s%%" % accuracy_after_vt1
            results["actually_malicious_vt10"] = actually_malicious_10
            results["accuracy_vt10"] = "%s%%" % round(accuracy_after_vt10*100.0, 2)
            results["actually_malicious_vt50p"] = actually_malicious_50p
            results["accuracy_vt50p"] = "%s%%" % round(accuracy_after_vt50p*100.0, 2)

        for r in results:
            prettyPrint("\"%s\": %s" % (r, results[r]), "output")

        if arguments.save == "yes":
            open(arguments.infile.replace(".txt", ".summary"), "w").write(str(results)) 


    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Good bye")
    return True

if __name__ == "__main__":
    main()
