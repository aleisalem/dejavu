#!/usr/bin/python

from dejavu.conf.config import *
from dejavu.utils.graphics import *
from dejavu.utils.data import *
from dejavu.utils.apkid import *
from dejavu.learning.feature_extraction import *
from dejavu.learning.scikit_learners import *
import pickle
from Levenshtein import distance
import argparse, os, glob, random, sys, operator, logging, shutil, time, signal
from exceptions import KeyError

def defineArguments():
    parser = argparse.ArgumentParser(prog="dejavu_tool_mkIV.py", description="Runs experiments using a sequential ensemble of dejavu's detection methods")
    parser.add_argument("-x", "--inputdir", help="The directory containing the APKs", required=True)
    parser.add_argument("-c", "--classifier", help="The path to the classifier trained using AMD+Gplay traces", required=False)
    parser.add_argument("-r", "--clusters", help="The path to the file containing the benign apps clusters", required=False)
    parser.add_argument("-i", "--infodir", help="The directory containing the pre-extracted app info used for APK matching", required=True)
    parser.add_argument("-a", "--apkdir", help="The directory containing the APK's of the benign apps", required=True)
    parser.add_argument("-f", "--featuretype", help="The type of features to consider", required=False, default="static", choices=["static", "dynamic"])
    parser.add_argument("-e", "--matchingdepth", help="The rigorosity of app matching", type=int, required=False, default=2, choices=[1,2,3,4])
    parser.add_argument("-t", "--matchingthreshold", help="The threshold beyond which apps are considered similar", required=False, default=0.8, type=float)
    parser.add_argument("-d", "--classthreshold", help="The classification confidence (percentage) used by naive Bayes classifiers to assign apps to classes", type=float, required=False, default=0.80)
    parser.add_argument("-l", "--experimentlabel", help="Give a label to the experiment currently run by the tool", required=False, default="Dejavu experiment")
    parser.add_argument("-y", "--experimenttype", help="Whether the experiment is performed on malicious or benign datasets", required=False, default="malicious", choices=["malicious", "benign"])
    parser.add_argument("-b", "--labeling", help="The type of labeling scheme to employ in deeming apps as [malicious-benign]", required=False, default="vt1-vt1", choices=["old", "vt1-vt1", "vt50p-vt50p", "vt50p-vt1"])
    parser.add_argument("-s", "--hustleup", help="Whether to use lookup structs to speed up the experiments", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-u", "--cleanup", help="Whether to remove the directories containing data about the analyzed and tested apps", required=False, default="no", choices=["yes", "no"])
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Yalla beena!!")
        
        logging.disable(50)
        # Retrieve the apps to be tested
        testAPKs = glob.glob("%s/*.apk" % arguments.inputdir)

        if len(testAPKs) < 1:
            prettyPrint("Could not find any APKs to classify. Exiting", "error")
            return False

        prettyPrint("Successfully retrieved %s apps" % (len(testAPKs)))

        # Load classifier
        prettyPrint("Loading the classifier under \"%s\"" % arguments.classifier)
        clf = pickle.loads(open(arguments.classifier).read())

        # Load necessary lookup structures
        prettyPrint("Loading package name clusters")
        clusters = eval(open(arguments.clusters).read())
        prettyPrint("Loading package name lookup dictionary")
        lookup = eval(open(arguments.clusters.replace("clusters", "pkgToHash")).read())
        

        # Keeping track of performance metrics 
        # Key: app path
        # Value: (package_name, compiler, analysis time, original_label, predicted_label, prediction_confidence, prediction_method, matched_path)
        performance = {}
        # Iterate over test APK's and classify them
        y, predicted = [], [] # Populate the ground truth at the end according to different labels
        matched, classified = 0.0, 0.0
        labels = ["Goodware", "Malware"]
        counter = 1
        for app in testAPKs:
            # Handle Ctrl+C events without losing data
            #def signal_handler(sig, frame):
            #    if len(performance) > 0:
            #        prettyPrint("Received Ctrl+C signal. Saving performance file", "error")
            #        open("Dejavu_results_%s_%s_%s_%s.txt" % (arguments.experimentlabel.replace(' ', '_'), arguments.matchingdepth, arguments.thresholds, arguments.labels), "w").write(str(performance))
            #    sys.exit(0)
            #signal.signal(signal.SIGINT, signal_handler)
            # End of Handle Ctrl+C events without losing data
            start_time = time.time() # Start timing classification here
            prettyPrint("Processing app \"%s\": #%s out of %s" % (app, counter, len(testAPKs)))
            predictedLabel = -1
            compiler, matched_with = "", ""
            # Extract static features from app
            if arguments.hustleup == "yes":
                if os.path.exists("%s/%s_data" % (arguments.infodir, app[app.rfind("/")+1:].replace(".apk", ""))):
                    if os.path.exists("%s/%s_data/data.txt" % (arguments.infodir, app[app.rfind("/")+1:].replace(".apk", ""))):
                        app_info = eval(open("%s/%s_data/data.txt" % (arguments.infodir, app[app.rfind("/")+1:].replace(".apk", ""))).read())
                        if len(app_info) < 1:
                            apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=arguments.matchingdepth)               
                            if not apk or not dex or not vm:
                                prettyPrint("Could not analyze app. Skipping", "warning")
                                continue
                    else:
                        apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=arguments.matchingdepth)
                        if not apk or not dex or not vm:
                            prettyPrint("Could not analyze app. Skipping", "warning")
                            continue
                else:
                    apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=arguments.matchingdepth)
                    if not apk or not dex or not vm:
                        prettyPrint("Could not analyze app. Skipping", "warning")
                        continue    
            else:
                apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=arguments.matchingdepth)
                if not apk or not dex or not vm:
                    prettyPrint("Could not analyze app. Skipping", "warning")
                    continue
              
            #####################
            # 1. Quick matching #
            #####################
            matchings = []
            randomLabels = []
            prettyPrint("Initializaing Quick matching")
            for cluster_name in clusters:
                matchings.append((cluster_name, distance(app_info["package"], cluster_name)))

            matchings.sort(key=operator.itemgetter(1))
            for m in matchings:
                for name in clusters[m[0]]:
                    if predictedLabel != -1:
                        prettyPrint("Label already assigned. Skipping", "debug")
                        continue
                    # Compute the distance between the current app's package name and the current cluster's center
                    score = stringRatio(app_info["package"], name)
                    if score >= arguments.matchingthreshold:
                        # Distance is greater than or equal matching threshold (d_match)
                        target_key = lookup[name]
                        prettyPrint("Match with \"%s\" of %s. Performing level 1 matching." % (target_key, score), "output")
                        if not os.path.exists("%s/%s_data" % (arguments.infodir, target_key)):
                            prettyPrint("Matched app has not been analyzed. Skipping", "warning")
                            continue

                        # Match the two apps
                        app_dir = "%s/%s_data" % (arguments.infodir, app[app.rfind("/")+1:].replace(".apk", "")) if arguments.hustleup == "yes" else "%s/tmp_%s" % (arguments.inputdir, app_info["package"])
                        prettyPrint("Matching \"%s\" and \"%s/%s_data/\"" % (app_dir, arguments.infodir, target_key), "debug")
                        similarity = matchTwoAPKs(app_dir, "%s/%s_data/" % (arguments.infodir, target_key), 1)
                        if similarity >= arguments.matchingthreshold:
                            # Retrieve more info about the match
                            if os.path.exists("%s/%s_data/data.txt" % (arguments.infodir, target_key)):
                                matched_info = eval(open("%s/%s_data/data.txt" % (arguments.infodir, target_key)).read())
                            # If still match, extract APKID info
                            prettyPrint("Fingerprinting \"%s\"'s compiler using APKiD" % app)
                            output = scan(app, 60, "yes")
                            try:
                                compiler = output["files"][0]["results"]["compiler"][0]
                            except Exception as e:
                                compiler = "n/a"

                            prettyPrint("App: \"%s\" was compiled using \"%s\"" % (app, compiler), "output")

                            # [PAPER] At this point, we matched original app (a) to test app (a*) (i.e., match(a, a*) >= t_match) 
                            # Figure out where the matched app resides
                            if os.path.exists("%s/GPlay/%s.apk" % (arguments.apkdir, target_key)):
                                matched_app = "%s/GPlay/%s.apk" % (arguments.apkdir, target_key)
                            elif os.path.exists("%s/Original/%s.apk" % (arguments.apkdir, target_key)):
                                matched_app = "%s/Original/%s.apk" % (arguments.apkdir, target_key)
                            elif os.path.exists("%s/Piggybacked/%s.apk" % (arguments.apkdir, target_key)):
                                matched_app = "%s/Piggybacked/%s.apk" % (arguments.apkdir, target_key)
                            elif os.path.exists("%s/Malgenome/%s.apk" % (arguments.apkdir, target_key)):
                                matched_app = "%s/Malgenome/%s.apk" % (arguments.apkdir, target_key)
                            else:
                                matched_app = None

                            # Get compiler of the matched app
                            if matched_app != None:
                                output = scan(matched_app, 60, "yes") 
                                try:
                                    matched_compiler = output["files"][0]["results"]["compiler"][0]
                                except Exception as e:
                                    matched_compiler = "n/a"
                            else:
                                matched_compiler = "n/a"

                            prettyPrint("Compiler of matched app is \"%s\"" % matched_compiler, "debug")

                            # [PAPER] Compare code(a*) and code(a) (i.e., minus resources)
                            # Expecting dictionary of {"differences": {[class_name]: [different_code]}, "original": [package_name], "piggybacked": [package_name]}
                            codeDiff = diffAppCode(app, matched_app, True)
                            if len(codeDiff) == 0:
                                predictedLabel = -1 # An exception has occurred (defer to clf)
                            # [PAPER] if code(a*) == code(a)
                            elif codeDiff["differences"] == False:
                                predictedLabel = 0 
                            # [PAPER] code(a*) != code(a)
                            # [PAPER] if comp(a) == dx && comp(a*) != dx
                            elif matched_compiler.lower().find("dx") != -1 and compiler.lower().find("dx") == -1:
                                predictedLabel = 1
                                    
                            # [PAPER] code(a*) != code(a) && ...
                            # [PAPER] Possible scenario(s):
			    # [PAPER]     (1) comp(a) == dx/dexmerge && comp(a*) == dx/dexmerge
			    # [PAPER]     (1) comp(a) == dexlib && comp(a*) == dx/dexmerge: 
			    # [PAPER]     (2) comp(a) == dexlib && comp(a*) == dexlib
                            else:
                                predictedLabel = -1


            prediction_method = "quick_matching"
            prediction_confidence = 1.0
            if predictedLabel == -1:
                prettyPrint("Quick matching could not assign a label.Skipping", "warning")
             
            if predictedLabel == -1:
                # Could not match using quick matching
                ###################################
                # 2. Probabilistic classification #
                ###################################
                prettyPrint("Classifying using Multinomial naive Bayes")
                if os.path.exists(app.replace(".apk", ".static")):
                    app_static_features = eval(open(app.replace(".apk", ".static")).read())
                else:
                    prettyPrint("Could not find pre-extracted static features for app \"%s\". Extracting" % app, "debug")
                    app_static_features = extractStaticFeatures(app)[-1]

                if len(app_static_features) < 1:
                    prettyPrint("Could not extract static features for app \"%s\"" % app, "warning")
                    predictedLabel = -1

                classes = clf.predict_proba(app_static_features).tolist()[0]
                prettyPrint("App \"%s\" classified as benign with P(C=0.0|app)=\"%s\" and as malicious with P(C=1.0|app)=\"%s\" " % (app, classes[0], classes[1]), "output")
                if max(classes) >= arguments.classthreshold:
                    predictedLabel = classes.index(max(classes))
                else:
                    prettyPrint("Probabilistic classification could not classify app. Skipping", "warning")
                    predictedLabel = -1
                    counter += 1

                prediction_method = "classification"
                prediction_confidence = max(classes)
                
            if predictedLabel == -1:
                # Could not classify with confidence using naive Bayes
                ########################
                # 3. Try deep matching #
                ########################
                prettyPrint("Commencing deep matching")
                useLookup = True if arguments.hustleup == "yes" else False
                matchings = matchAPKs(app, arguments.infodir, matchingDepth=arguments.matchingdepth, matchWith=10, labeling=arguments.labeling, useLookup=useLookup)
                prettyPrint("Successfully matched app \"%s\" with %s apps" % (app, len(matchings)))
                malicious = 0
                if len(matchings) > 0:
                    # [('com.getbux.android', (0.575, 0)), .... ]
                    for m in matchings:
                        key, value = m[0], m[1]
                        color = "error" if value[1] == 1 else "debug"
                        prettyPrint("Matched with \"%s\" with similarity %s" % (key, value[0]), color)
                        if value[1] == 1:
                            malicious += 1

                else:
                    prettyPrint("Could not match app. Skipping", "warning")
                    counter += 1
                    continue

                predictedLabel = 1 if malicious >= len(matchings)/2.0 else 0
                prediction_method = "deep_matching"
                prediction_confidence = len(matchings)/2.0

            # Retrieve and append the app's original label according to the labeling scheme
            originalLabel = -1
            app_key = app[app.rfind("/")+1:].replace(".apk", "")
            if arguments.labeling == "old":
                originalLabel = 1 if arguments.experimenttype == "malicious" else 0
            else:
                if os.path.exists("%s/%s.report" % (VT_REPORTS_DIR, app_key)):
                    prettyPrint("VirusTotal report found", "debug")
                    report = eval(open("%s/%s.report" % (VT_REPORTS_DIR, app_key)).read())
                    if "positives" in report.keys():
                        if arguments.labeling == "vt1-vt1":
                            originalLabel = 1 if report["positives"] >= 1 else 0
                        elif arguments.labeling == "vt50p-vt50p":
                            originalLabel = 1 if report["positives"]/float(report["total"]) >= 0.5 else 0
                        elif arguments.labeling == "vt50p-vt1":
                            if report["positives"]/float(report["total"]) >= 0.5:
                                originalLabel = 1
                            elif report["positives"] == 0:
                                originalLabel = 0
                            else:
                                originalLabel = -1

            if originalLabel != -1:
                y.append(originalLabel)
                # Append results to lists
                predicted.append(predictedLabel)
                end_time = time.time() # End timing classification here
                prettyPrint("%s app \"%s\" classified as %s" % (labels[originalLabel], app[app.rfind('/')+1:], labels[predictedLabel]), "info2")
                # Add record to performance
                #compiler = compiler if prediction_method == "quick_matching" else "n/a"
                matched_with = target_key if prediction_method == "quick_matching" else "n/a"
                if compiler == "":
                    # No apps were matched to (a*), extract compiler now
                    output = scan(app, 60, "yes")
                    try:
                        compiler = output["files"][0]["results"]["compiler"][0]
                    except Exception as e:
                        compiler = "n/a"

            if predictedLabel != -1 and originalLabel != -1:
                # (package_name, compiler, analysis time, original_label, predicted_label, prediction_confidence, prediction_method, matched_path)
                performance[app] = (app_info["package"], compiler, end_time-start_time, originalLabel, predictedLabel, prediction_confidence, prediction_method, matched_with)
                counter += 1

        # Calculate the accuracies according to different VT labeling schemes
        metrics_all = calculateMetrics(y, predicted)
        print y, predicted
        prettyPrint("Accuracy: %s" % metrics_all["accuracy"], "output")
        prettyPrint("Precision: %s" % metrics_all["precision"], "output")
        prettyPrint("Recall: %s" % metrics_all["recall"], "output")
        prettyPrint("Specificity: %s" % metrics_all["specificity"], "output")
        prettyPrint("F1 Score: %s" % metrics_all["f1score"], "output")
        # Save gathered performance metrics
        fileName = "Dejavu_results_ensemble_%s_%s_%s_%s_%s.txt" % (arguments.experimentlabel, arguments.labeling, arguments.matchingthreshold, arguments.classthreshold, arguments.matchingdepth)
        open(fileName.replace(' ', '_'), "w").write(str(performance))

        # Clean up?         
        if arguments.cleanup == "yes":
            prettyPrint("Cleaning up")
            for directory in glob.glob("%s/tmp_*" % arguments.inputdir):
                shutil.rmtree(directory)

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Salam ya me3allem!")
    return True

if __name__ == "__main__":
    main()
