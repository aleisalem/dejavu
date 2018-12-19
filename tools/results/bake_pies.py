#!/usr/bin/python

import glob
import sys
import matplotlib.pyplot as plt
import matplotlib as mpl

CMYK = ["#c0c0c0", "#808080", "#505050", "#000000"] # Grayscale colors
RGB = ["#ff4136", "#3d9970", "#ff851b", "#6baed6", "#808389", "48494c"] # Normal colors

def main():
    # 1. Retrieve arguments
    if len(sys.argv) < 5:
        print "[*] USAGE: python bake_pies.py [dataset] [thresholds] [depth] [colors]"
        return False

    dataset = sys.argv[1]
    thresholds = "*" if sys.argv[2] == "all" else sys.argv[2]
    depth = "*" if sys.argv[3] == "all" else sys.argv[3]
    colors = sys.argv[4]
    
    # 2. Retrieve files
    files = glob.glob("Dejavu_results_%s_%s_%s.txt" % (dataset, depth, thresholds))
    if len(files) < 1:
        print "[*] Could not retrieve files with the pattern \"Dejavu_results_%s_*_%s_%s.txt\"" % (dataset, depth, thresholds)
        return False

    print "[*] Successfully retrieved %s data files" % len(files)
    
    # 3. Parse data files and collect data
    files.sort()
    for f in files:
        print "[*] Processing data in \"%s\"" % f
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
    clrs = CMYK[:len(labels)] if colors == "CMYK" else RGB[:len(labels)]

    mpl.rcParams['font.size'] = 15.0
    centre_circle = plt.Circle((0,0),0.80,fc='white')
    fig, ax = plt.subplots()
    ax.pie(sizes, labels=labels, autopct='%1.2f%%', startangle=90, colors=clrs)
    fig = plt.gcf()
    fig.gca().add_artist(centre_circle)
   
    ax.axis('equal')
    plt.tight_layout()
    #plt.show()
    plt.savefig('Pie_%s_%s_%s.pdf' % (dataset, thresholds, depth))
    plt.savefig('Pie_%s_%s_%s.pgf' % (dataset, thresholds, depth))
    

        

if __name__ == "__main__":
    main()
