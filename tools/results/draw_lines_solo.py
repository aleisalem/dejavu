#!/usr/bin/python

import glob, sys, argparse
from numpy import median
import numpy as np
import matplotlib.pyplot as plt
from dejavu.utils.graphics import *


CMYK = ["#c0c0c0", "#808080", "#505050", "#000000"] # Grayscale colors
RGB = ["#ff4136", "#3d9970", "#ff851b", "#6baed6", "#808389", "48494c"] # Normal colors

def defineArguments():
    parser = argparse.ArgumentParser(prog="draw_lines_solo.py", description="Generates line plots per detection method per labeling scheme")
    parser.add_argument("-i", "--indir", help="The directory where the results files can be found", required=True)
    parser.add_argument("-l", "--labeling", help="The labeling scheme adopted during the experiments", required=True, choices=["old", "vt1-vt1", "vt50p-vt50p", "vt50p-vt1"])
    parser.add_argument("-m", "--method", help="The detection method to consider in plotting", required=False, default="quick_matching", choices=["quick_matching", "prob_classifier", "deep_matching"])
    parser.add_argument("-c", "--colors", help="The coloring theme of the pie charts", required=False, choices=["cmyk", "rgb"], default="rgb")
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Get in line!!")

        # 2. Retrieve files
        pattern = "%s/Dejavu_results_%s_*_%s_*.txt" % (arguments.indir, arguments.method, arguments.labeling) 
        files = glob.glob(pattern)
        if len(files) < 1:
            prettyPrint("Could not retrieve files with the pattern \"%s\"" % pattern, "warning")
            return False

        prettyPrint("Successfully retrieved %s data files" % len(files))
 
        # 3. Parse data files and collect data
        files.sort()
        Xmal, Ymal, Vmal, = [], [], {}
        Xpiggy, Ypiggy, Vpiggy = [], [], {}
        Xorg, Yorg, Vorg = [], [], {}
        for f in files:
            prettyPrint("Processing data in \"%s\"" % f)
            current_var = f[f.rfind('_')+1:].replace(".txt", "")
            data = eval(open(f).read())
            val = current_var
            if f.lower().find("malgenome") != -1:
                 if not val in Xmal:
                     Xmal.append(val)
                     Vmal[val] = []
            elif f.lower().find("piggyback") != -1:
                if not val in Xpiggy:
                    Xpiggy.append(val)
                    Vpiggy[val] = []
            else:
                if not val in Xorg:
                    Xorg.append(val)
                    Vorg[val] = []

           # Retrieve data from a file
            a = 0.0
            for k in data:
                datapoint = data[k]
                if datapoint[3] == datapoint[4]:
                    a += 1.0

            acc = round(a/len(data), 2)
            if f.lower().find("malgenome") != -1:
                Vmal[val].append(acc)
            elif f.lower().find("piggyback") != -1:
                Vpiggy[val].append(acc)
            else:
                Vorg[val].append(acc)
         
 
        for key in Xmal:
            Ymal.append(Vmal[key])#round(float(sum(Vmal[key]))/len(Xmal), 2))
        for key in Xpiggy:
            Ypiggy.append(Vpiggy[key])#round(float(sum(Vpiggy[key]))/len(Xpiggy), 2))
        for key in Xorg:
            Yorg.append(Vorg[key])#round(float(sum(Vorg[key]))/len(Xorg), 2))
    
        print Xmal, Ymal
        print Xpiggy, Ypiggy
        print Xorg, Yorg
        # Build figure
        # General stuff
        fig, ax1 = plt.subplots()
        clrs = [] + CMYK if arguments.colors == "cmyk" else [] + RGB
        x = range(1,len(Xmal)+1)
        plt.xticks(x, Xmal)#, rotation=45)
        if arguments.method == "quick_matching":
            xlabel = "Matching Threshold"
        elif arguments.method == "prob_classifier":
            xlabel = "Classification Threshold"
        else:
            xlabel = "Matching Depth"
        ax1.set_xlabel(xlabel, size=12)
        # First half of figure
        ax1.set_ylabel("Classification Accuracy", color=clrs[-1], size=12)
        ax1.tick_params(axis='y', labelcolor="#000000")
        ax1.plot(x, Ymal, color=clrs[0], marker='o') # Malgenome
        ax1.plot(x, Ypiggy, color=clrs[1], marker='^') # Piggybacked
        ax1.plot(x, Yorg, color=clrs[2], marker='s') # Original
        plt.legend(["Malgenome", "Piggybacked", "Original"], loc="best", fontsize="small").get_frame().set_alpha(0.5) 
        if arguments.method == "deep_matching":
            plt.ylim(0.3, 1.1)
        elif arguments.method == "quick_matching":
            plt.ylim(0.5, 1.1)
        else:
            plt.ylim(0.2, 1.1)
        plt.setp(ax1.get_yticklabels()[-1], visible=False)
        fig.tight_layout()
        #plt.show()
        plt.savefig("Line_%s_%s.pdf" % (arguments.method, arguments.labeling))
        plt.savefig("Line_%s_%s.pgf" % (arguments.method, arguments.labeling))

    except Exception as e:
        prettyPrintError(e)
        return False


    prettyPrint("Don't get tangled in them lines!!")
    return True
            

if __name__ == "__main__":
    main()
