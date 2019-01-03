#!/usr/bin/python

import glob
import sys, argparse
import matplotlib.pyplot as plt
import matplotlib as mpl
from dejavu.utils.graphics import *

CMYK = ["#c0c0c0", "#808080", "#505050", "#000000"] # Grayscale colors
RGB = ["#ff4136", "#3d9970", "#ff851b", "#6baed6", "#808389", "48494c"] # Normal colors

def defineArguments():
    parser = argparse.ArgumentParser(prog="bake_pies.py", description="Plots the distribution of matching techniques that correctly classified APKs in a dataset as a pie chart")
    parser.add_argument("-i", "--dataset", help="The experiment label given to files (e.g., Piggybacked, Original, Malgenome, etc.)", required=True)
    parser.add_argument("-l", "--labeling", help="The labeling scheme adopted during the experiments", required=True, choices=["vt1-vt1", "vt50p-vt50p", "vt50p-vt1"])
    parser.add_argument("-d", "--depth", help="The matching depth adopted during the experiments", required=False, default="all")
    parser.add_argument("-t", "--thresholds", help="The matching and classification thresholds adopted during the experiments", required=False, default="all")
    parser.add_argument("-c", "--colors", help="The coloring theme of the pie charts", required=False, choices=["cmyk", "rgb"], default="rgb")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Backen backen Kuchen!!")

        # 2. Retrieve files
        files = glob.glob("Dejavu_results_%s_%s_%s.txt" % (arguments.dataset, arguments.labeling, arguments.depth, arguments.thresholds))
        if len(files) < 1:
            prettyPrint("Could not retrieve files with the pattern \"Dejavu_results_%s_*_%s_%s_%s.txt\"" % (arguments.dataset, arguments.labeling, arguments.depth, arguments.thresholds), "warning")
            return False

        prettyPrint("Successfully retrieved %s data files" % len(files))
      
        # 3. Parse data files and collect data
        files.sort()
        for f in files:
            prettyPrint("Processing data in \"%s\"" % f)
            data = eval(open(f).read())
            correct = 0.0
            quick, deep, clf = 0.0, 0.0, 0.0
            t_quick, t_deep, t_clf = [], [], []
            for k in data:
                datapoint = data[k]
                if datapoint[3] == datapoint[4]:
                    correct += 1.0
                    if datapoint[6] == "quick_matching":
                        quick += 1.0
                        t_quick.append(datapoint[2])
                    elif datapoint[6] == "classification":
                        clf += 1.0
                        t_clf.append(datapoint[2])
                    else:
                        deep += 1.0
                        t_deep.append(datapoint[2])

        # Build the pie chart
        sizes = []
        times = []
        labels = []
        if len(t_quick) != 0:
            times.append(sum(t_quick)/len(t_quick))
            sizes.append(quick/correct)
            labels.append("Quick Matching\n %s (sec)" % round(times[0], 2))
        if len(t_clf) != 0:
            times.append(sum(t_clf)/len(t_clf))
            sizes.append(clf/correct)
            labels.append("Probabilistic Classification\n %s (sec)" % round(times[1], 2))
        if len(t_deep) != 0:
            times.append(sum(t_deep)/len(t_deep))
            sizes.append(deep/correct)
            labels.append("Deep Matching\n %s (sec)" % round(times[2], 2))

        explode = [0.0, 0.0, 0.0]
        explode[sizes.index(max(sizes))] = 0.1
        explode = tuple(explode)
        clrs = CMYK[:len(labels)] if arguments.colors == "CMYK" else RGB[:len(labels)]

        mpl.rcParams['font.size'] = 15.0
        centre_circle = plt.Circle((0,0),0.80,fc='white')
        fig, ax = plt.subplots()
        ax.pie(sizes, labels=labels, autopct='%1.2f%%', startangle=90, colors=clrs)
        fig = plt.gcf()
        fig.gca().add_artist(centre_circle)
     
        ax.axis('equal')
        plt.tight_layout()
        #plt.show()
        plt.savefig('Pie_%s_%s_%s_%s.pdf' % (arguments.dataset, arguments.labeling, arguments.thresholds, arguments.depth))
        plt.savefig('Pie_%s_%s_%s_%s.pgf' % (arguments.dataset, arguments.labeling, arguments.thresholds, arguments.depth))

    except Exception as e:
        prettyPrintError(e)
        return False


    prettyPrint("Bis spaeter!") 
    return True
    
if __name__ == "__main__":
    main()
