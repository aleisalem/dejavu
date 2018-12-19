#!/usr/bin/python

import glob, sys
from numpy import median
import numpy as np
import matplotlib.pyplot as plt


CMYK = ["#c0c0c0", "#808080", "#505050", "#000000"] # Grayscale colors
RGB = ["#ff4136", "#3d9970", "#ff851b", "#6baed6", "#808389", "48494c"] # Normal colors

def main():
    # 1. Retrieve arguments
    if len(sys.argv) < 3:
        print "[*] USAGE: python draw_lines.py [plot_type] [colors]"
        print "\t\t plot_type: acc-depth, acc-thresholds, time-depth, or time-thresholds"
        return False

    plot_type = sys.argv[1]
    colors = sys.argv[2]

    # 2. Retrieve files
    files = glob.glob("Dejavu_results_*.txt")
    if len(files) < 1:
        print "[*] Could not retrieve files with the pattern \"Dejavu_results_%s_*.txt\"" % dataset
        return False

    print "[*] Successfully retrieved %s data files" % len(files)

    # 3. Parse data files and collect data
    files.sort()
    Xmal, Ymal, Vmal = [], [], {}
    Xpiggy, Ypiggy, Vpiggy = [], [], {}
    Xorg, Yorg, Vorg = [], [], {}
    for f in files:
        print "[*] Processing data in \"%s\"" % f
        current_threshold = f[f.rfind('_')+1:].replace(".txt", "")
        current_depth = f[:f.rfind('_')][f[:f.rfind('_')].rfind('_')+1:]
        data = eval(open(f).read())
        val  = current_depth if plot_type.find("depth") != -1 else current_threshold
        if f.lower().find("malgenome") != -1:
             if not val in Xmal:
                 Xmal.append(val)
                 Vmal[val] = []
        elif f.lower().find("piggybacked") != -1:
            if not val in Xpiggy:
                Xpiggy.append(val)
                Vpiggy[val] = []
        else:
            if not val in Xorg:
                Xorg.append(val)
                Vorg[val] = []

        # Retrieve data from a file
        t = 0.0
        a = 0.0
        for k in data:
            datapoint = data[k]
            t += datapoint[2]
            if datapoint[3] == datapoint[4]:
                a += 1.0

        tavg = round(t/len(data), 2) # Average time per file
        acc = round(a/len(data), 2)
        val2 = tavg if plot_type.find("time") != -1 else acc
        if f.lower().find("malgenome") != -1:
            Vmal[val].append(val2)
        elif f.lower().find("piggybacked") != -1:
            Vpiggy[val].append(val2)
        else:
            Vorg[val].append(val2)
         
 
    for key in Xmal:
        Ymal.append(round(float(sum(Vmal[key]))/len(Xmal), 2))
    for key in Xpiggy:
        Ypiggy.append(round(float(sum(Vpiggy[key]))/len(Xpiggy), 2))
    for key in Xorg:
        Yorg.append(round(float(sum(Vorg[key]))/len(Xorg), 2))
    
    print Xmal, Ymal
    print Xpiggy, Ypiggy
    print Xorg, Yorg
    # Build figure
  
    clrs = [] + CMYK if colors == "CMYK" else [] + RGB
    x = range(1,len(Xmal)+1)
    plt.xticks(x, Xmal)#, rotation=45)
    plt.plot(x, Ymal, color=clrs[0], marker='o') # Malgenome
    plt.plot(x, Ypiggy, color=clrs[1], marker='^') # Piggybacked
    plt.plot(x, Yorg, color=clrs[2], marker='s') # Original ...., linestyle='dashed', linewidth=2) # F1 Permissions (Static)

    plt.legend(["Malgenome", "Piggybacked", "Original"], loc="lower right", fontsize="small").get_frame().set_alpha(0.5)
    xlabel = "Matching Depth" if plot_type.find("depth") !=-1 else "Matching+Classification Thresholds"
    ylabel = "Time (seconds)" if plot_type.find("time") != -1 else "Classification Accuracy"
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    #plt.show()
    plt.savefig("Line_%s.pdf" % plot_type.replace('-', '_'))
    plt.savefig("Line_%s.pgf" % plot_type.replace('-', '_'))
            

if __name__ == "__main__":
    main()
