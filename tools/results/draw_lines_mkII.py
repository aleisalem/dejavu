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
        print "\t\t plot_type: depth or thresholds"
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
    Xmal, Ymal, Ymal2, Vmal, Vmal2 = [], [], [], {}, {}
    Xpiggy, Ypiggy, Ypiggy2, Vpiggy, Vpiggy2 = [], [], [], {}, {}
    Xorg, Yorg, Yorg2, Vorg, Vorg2 = [], [], [], {}, {}
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
                 Vmal2[val] = []
        elif f.lower().find("piggybacked") != -1:
            if not val in Xpiggy:
                Xpiggy.append(val)
                Vpiggy[val] = []
                Vpiggy2[val] = []
        else:
            if not val in Xorg:
                Xorg.append(val)
                Vorg[val] = []
                Vorg2[val] = []

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
        if f.lower().find("malgenome") != -1:
            Vmal[val].append(acc)
            Vmal2[val].append(tavg)
        elif f.lower().find("piggybacked") != -1:
            Vpiggy[val].append(acc)
            Vpiggy2[val].append(tavg)
        else:
            Vorg[val].append(acc)
            Vorg2[val].append(tavg)
         
 
    for key in Xmal:
        Ymal.append(round(float(sum(Vmal[key]))/len(Xmal), 2))
        Ymal2.append(round(float(sum(Vmal2[key]))/len(Xmal), 2))
    for key in Xpiggy:
        Ypiggy.append(round(float(sum(Vpiggy[key]))/len(Xpiggy), 2))
        Ypiggy2.append(round(float(sum(Vpiggy2[key]))/len(Xpiggy), 2))
    for key in Xorg:
        Yorg.append(round(float(sum(Vorg[key]))/len(Xorg), 2))
        Yorg2.append(round(float(sum(Vorg2[key]))/len(Xorg), 2))
    
    print Xmal, Ymal, Ymal2
    print Xpiggy, Ypiggy, Ypiggy2
    print Xorg, Yorg, Yorg2
    # Build figure
    # General stuff
    fig, ax1 = plt.subplots()
    clrs = [] + CMYK if colors == "CMYK" else [] + RGB
    x = range(1,len(Xmal)+1)
    plt.xticks(x, Xmal)#, rotation=45)
    xlabel = "Matching Depth" if plot_type.find("depth") !=-1 else "Matching+Classification Thresholds"
    ax1.set_xlabel(xlabel, size=12)
    # First half of figure
    ax1.set_ylabel("Classification Accuracy", color=clrs[1], size=12)
    ax1.tick_params(axis='y', labelcolor=clrs[1])
    ax1.plot(x, Ymal, color=clrs[0], marker='o') # Malgenome
    ax1.plot(x, Ypiggy, color=clrs[0], marker='^') # Piggybacked
    ax1.plot(x, Yorg, color=clrs[0], marker='s') # Original
    # Second half of figure
    ax2 = ax1.twinx()
    ax2.set_ylabel("Time (seconds)", color=clrs[-1], size=12)
    ax2.tick_params(axis='y', labelcolor=clrs[-1])
    ax2.plot(x, Ymal2, color=clrs[2], marker='o', linestyle='dashed', linewidth=2) # Malgenome
    ax2.plot(x, Ypiggy2, color=clrs[2], marker='^', linestyle='dashed', linewidth=2) # Piggybacked
    ax2.plot(x, Yorg2, color=clrs[2], marker='s', linestyle='dashed', linewidth=2) # Original
    plt.legend(["Malgenome", "Piggybacked", "Original"], loc="best", fontsize="small").get_frame().set_alpha(0.5) 
    fig.tight_layout()
    #plt.show()
    plt.savefig("Line_II_%s.pdf" % plot_type)
    plt.savefig("Line_II_%s.pgf" % plot_type)
            

if __name__ == "__main__":
    main()
