#!/usr/bin/python

import glob
import sys, argparse
import matplotlib.pyplot as plt
import matplotlib as mpl
import numpy as np
from dejavu.utils.graphics import *

CMYK = ["#c0c0c0", "#808080", "#505050", "#000000"] # Grayscale colors
RGB = ["#ff4136", "#3d9970", "#ff851b", "#6baed6", "#808389", "48494c"] # Normal colors

def defineArguments():
    parser = argparse.ArgumentParser(prog="bake_pies.py", description="Plots the distribution of matching techniques that correctly classified APKs in a dataset as a pie chart")
    parser.add_argument("-i", "--indir", help="The directory in which the data files reside", required=True)
    parser.add_argument("-p", "--pattern", help="The pattern used to match and retrieve apps", required=True)
    parser.add_argument("-c", "--colors", help="The coloring theme of the pie charts", required=False, choices=["cmyk", "rgb"], default="rgb")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Backen backen Kuchen!!")

        # 2. Retrieve files
        files = glob.glob("%s/Dejavu_results_%s*.txt" % (arguments.indir, arguments.pattern))
        if len(files) < 1:
            prettyPrint("Could not retrieve files with the pattern \"Dejavu_results_%s*.txt\"" % arguments.pattern, "warning")
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
        tmps = []
        if len(t_quick) != 0:
            if quick/correct >= 0.01:
                times.append(sum(t_quick)/len(t_quick))
                sizes.append(quick/correct)
                labels.append("QM %s (sec)" % round(times[0], 2))
            else:
                tmps.append(sum(t_quick)/len(t_quick))
        if len(t_clf) != 0:
            if clf/correct >= 0.01:
                times.append(sum(t_clf)/len(t_clf))
                sizes.append(clf/correct)
                labels.append("PC %s (sec)" % round(times[1], 2))
            else:
                tmps.append(sum(t_clf)/len(t_clf))
        if len(t_deep) != 0:
            if deep/correct >= 0.01:
                times.append(sum(t_deep)/len(t_deep))
                sizes.append(deep/correct)
                labels.append("DM %s (sec)" % round(times[2], 2))
            else:
                tmps.append(sum(t_deep)/len(t_deep))

        clrs = CMYK[:len(labels)] if arguments.colors == "cmyk" else RGB[:len(labels)]
        print [quick/correct, clf/correct, deep/correct]
        print labels
        print tmps
 
        fig, ax = plt.subplots(figsize=(6, 3), subplot_kw=dict(aspect="equal"))
        wedges, texts = ax.pie(sizes, wedgeprops=dict(width=0.5), startangle=-40, colors=clrs)

        bbox_props = dict(boxstyle="square,pad=0.3", fc="w", ec="k", lw=0.72)
        kw = dict(xycoords='data', textcoords='data', arrowprops=dict(arrowstyle="-"), bbox=bbox_props, zorder=0, va="center")
 
        for i, p in enumerate(wedges):
            ang = (p.theta2 - p.theta1)/2. + p.theta1
            y = np.sin(np.deg2rad(ang))
            x = np.cos(np.deg2rad(ang))
            horizontalalignment = {-1: "right", 1: "left"}[int(np.sign(x))]
            connectionstyle = "angle,angleA=0,angleB={}".format(ang)
            kw["arrowprops"].update({"connectionstyle": connectionstyle})
            ax.annotate(labels[i], xy=(x, y), xytext=(1.35*np.sign(x), 1.4*y), horizontalalignment=horizontalalignment, **kw)
 
        #explode = [0.0] * len(sizes)
        #explode[sizes.index(max(sizes))] = 0.1
        #explode = tuple(explode)

        #mpl.rcParams['font.size'] = 10.0
        #centre_circle = plt.Circle((0,0),0.80,fc='white')
        #fig, ax = plt.subplots()
        #ax.pie(sizes, labels=labels, autopct='%1.2f%%', startangle=90, colors=clrs)
        #fig = plt.gcf()
        #fig.gca().add_artist(centre_circle)
     
        #ax.axis('equal')
        #plt.tight_layout()
        #plt.show()
        plt.savefig('Pie_%s.pdf' % arguments.pattern)
        plt.savefig('Pie_%s.pgf' % arguments.pattern)

    except Exception as e:
        prettyPrintError(e)
        return False


    prettyPrint("Bis spaeter!") 
    return True
    
if __name__ == "__main__":
    main()
