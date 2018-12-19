#!/usr/bin/python

import glob
import sys

def main():
    # 1. Retrieve arguments
    if len(sys.argv) < 4:
        print "[*] USAGE: python print_summary.py [dataset] [thresholds] [depth]"
        return False

    dataset = sys.argv[1]
    thresholds = "*" if sys.argv[2] == "all" else sys.argv[2]
    depth = "*" if sys.argv[3] == "all" else sys.argv[3]
    
    # 2. Retrieve files
    files = glob.glob("Dejavu_results_%s_%s_%s.txt" % (dataset, depth, thresholds))
    if len(files) < 1:
        print "[*] Could not retrieve files with the pattern \"Dejavu_results_%s_*_%s_%s.txt\"" % (dataset, depth, thresholds)
        return False

    print "[*] Successfully retrieved %s data files" % len(files)
    
    # 3. Parse data files and collect data
    files.sort()
    performance = {"total": [], "times": [], "accuracies": [], "false": [], "quick_matching": [], "classification": [], "deep_matching": []}
    for f in files:
        print "[*] Processing data in \"%s\"" % f
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
                
    print "[*] Dataset: %s, thresholds: %s, depth: %s" % (dataset, thresholds, depth)
    print "[*] Average total: %s" % total
    print "[*] Average Accuracy: %s" % accuracy
    print "[*] Average False (P/N): %s" % false
    print "[*] Average time (in seconds): %s" % time
    print "[*] Avg. quick: %s, avg. classification: %s, avg. deep: %s" % (quick, clf, deep)
        

if __name__ == "__main__":
    main()
