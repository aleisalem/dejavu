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
    parser = argparse.ArgumentParser(prog="dejavu_tool.py", description="Implements the hybrid process to detect repackaged malware")
    parser.add_argument("-x", "--inputdir", help="The directory containing the APKs", required=True)
    parser.add_argument("-c", "--classifier", help="The path to the classifier trained using AMD+Gplay traces", required=False, default="classifier.txt")
    parser.add_argument("-i", "--infodir", help="The directory containing the pre-extracted app info used for APK matching", required=True)
    parser.add_argument("-a", "--apkdir", help="The directory containing the APK's of the benign apps", required=True)
    parser.add_argument("-f", "--featuretype", help="The type of features to consider", required=False, default="static", choices=["static", "dynamic"])
    parser.add_argument("-e", "--matchingdepth", help="The rigorosity of app matching", type=int, required=False, default=1, choices=[1,2,3,4])
    parser.add_argument("-t", "--matchingthreshold", help="The percentage beyond which apps are considered similar", type=float, required=False, default=0.8)
    parser.add_argument("-s", "--classthreshold", help="The classification confidence (percentage) used by naive Bayes classifiers to assign apps to classes", type=float, required=False, default=0.80)
    parser.add_argument("-l", "--experimentlabel", help="Give a label to the experiment currently run by the tool", required=False, default="Dejavu experiment")
    parser.add_argument("-u", "--cleanup", help="Whether to remove the directories containing data about the analyzed and tested apps", required=False, default="no", choices=["yes", "no"])
    return parser

def main():
    try:
        argumentParser = defineArguments()
        arguments = argumentParser.parse_args()
        prettyPrint("Los geht's!!")
        

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
        clusters = eval(open("%s/clusters_all.txt" % LOOKUP_STRUCTS).read())
        prettyPrint("Loading package name lookup dictionary")
        lookup = eval(open("%s/package_to_hash.txt" % LOOKUP_STRUCTS).read())
        prettyPrint("Loading app compilers lookup")
        compilers = eval(open("%s/app_compilers.txt" % LOOKUP_STRUCTS).read())
        

        # Keeping track of performance metrics 
        # Key: app path
        # Value: (package_name, compiler, analysis time, original_label, predicted_label, prediction_confidence, prediction_method, matched_path)
        performance = {}
        # Iterate over test APK's and classify them
        y, predicted = [], []
        matched, classified = 0.0, 0.0
        labels = ["Goodware", "Malware"]
        for app in testAPKs:
            # Handle Ctrl+C events without losing data
            def signal_handler(sig, frame):
                if len(performance) > 0:
                    prettyPrint("Received Ctrl+C signal. Saving performance file", "error")
                    open("Dejavu_results_%s_%s_%s.txt" % (arguments.experimentlabel.replace(' ', '_'), arguments.matchingdepth, arguments.matchingthreshold), "w").write(str(performance))
                sys.exit(0)
            signal.signal(signal.SIGINT, signal_handler)
            # End of Handle Ctrl+C events without losing data
            start_time = time.time() # Start timing classification here
            prettyPrint("Processing app \"%s\"" % app)
            originalLabel = 1 if app.find("malware") != -1 else 0
            y.append(originalLabel)
            predictedLabel = -1
            # Extract static features from app
            apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=arguments.matchingdepth)
            if not apk or not dex or not vm:
                prettyPrint("Could not analyze app. Skipping", "warning")
                # Add a random label to maintain the same dimensionality between (y) and (predicted)
                predicted.append(float(random.randint(0,1)))
                continue
              
            #####################
            # 1. Quick matching #
            #####################
            matchings = []
            for cluster_name in clusters:
                matchings.append((cluster_name, distance(app_info["package"], cluster_name)))

            matchings.sort(key=operator.itemgetter(1))
            for m in matchings:
                for name in clusters[m[0]]:
                    # Compute the distance between the current app's package name and the current cluster's center
                    score = stringRatio(app_info["package"], name)
                    if score >= arguments.matchingthreshold:
                        # Distance is greater than or equal matching threshold (d_match)
                        target_key = lookup[name]
                        prettyPrint("Match with \"%s\" of %s. Performing level 1 matching." % (target_key, score), "output")
                        prettyPrint("Matching \"%s/tmp_%s/\" and \"%s/%s_data/\"" % (arguments.inputdir, app_info["package"], arguments.infodir, target_key), "debug")
                        similarity = matchTwoAPKs("%s/tmp_%s/" % (arguments.inputdir, app_info["package"]), "%s/%s_data/" % (arguments.infodir, target_key), 1)
                        if similarity >= arguments.matchingthreshold:
                            # Retrieve more info about the match
                            if os.path.exists("%s/%s_data/data.txt" % (arguments.infodir, target_key)):
                                matched_info = eval(open("%s/%s_data/data.txt" % (arguments.infodir, target_key)).read())
                            # If still match, extract APKID info
                            prettyPrint("Fingerprinting \"%s\"'s compiler using APKiD" % app)
                            output = scan(app, 60, "yes")
                            try:
                                compiler = output["files"][0]["results"]["compiler"][0]
                            except KeyError as ke:
                                compiler = "n/a"
                            prettyPrint("App: \"%s\" was compiled using \"%s\"" % (app, compiler), "output")
                            matched_compiler = compilers[target_key] if target_key in compilers.keys() else "n/a"
                            prettyPrint("Compiler of matched app is \"%s\"" % matched_compiler, "debug")

                            # [PAPER] At this point, we matched original app (a) to test app (a*) (i.e., match(a, a*) >= t_match) 
                            # Figure out where the matched app resides
                            if os.path.exists("%s/GPlay/%s.apk" % (arguments.apkdir, target_key)):
                                matched_app = "%s/GPlay/%s.apk" % (arguments.apkdir, target_key)
                            elif os.path.exists("%s/Original/%s.apk" % (arguments.apkdir, target_key)):
                                matched_app = "%s/Original/%s.apk" % (arguments.apkdir, target_key)
                            else:
                                matched_app = None
                            if compiler.lower().find("dx") != -1 or compiler.lower().find("dexmerge") != -1:
                                # [PAPER] If compiler(a*) == dx/dexmerge:
                                # [PAPER] Common theme: access to source code - scenario (5)
                                # [PAPER] Scenario(s): (1) App (a*) is the same benign app, (2) app (a*) is a malicious app written from scratch to resemble (a),
                                # [PAPER] ............ (3) app (a*) is malicious written by same author, (4) app (a*) is repackaged version of (a) whose code is available,
                                # [PAPER] ............ (5) app (a*) is repackaged version of (a) with forged compiler
                                if matched_compiler == compiler:
                                    # [PAPER] compiler(a) = compiler(a*) (dx vs. dx)
                                    # [PAPER] Compare code(a*) and code(a) (i.e., minus resources)
                                    if matched_app:
                                        # Found the APK of the matched app (This should always be true, but in case we clean up manually misclassified apps)
                                        prettyPrint("Comparing the source code of \"%s\" and \"%s\"" % (app, matched_app), "debug")
                                        codeDiff = diffAppCode(app, matched_app, True) # Run in fast mode (any difference, return True)
                                        # Expecting dictionary of {"differences": {[class_name]: [different_code]}, "original": [package_name], "piggybacked": [package_name]}
                                        if len(codeDiff) == 0:
                                            # That means that an exception has occurred and the returned dictionary is empty (Defer to clf)
                                            predictedLabel = -1
                                        else:
                                            if codeDiff["differences"] == True:
                                                # [PAPER] code(a*) != code(a): Assume scenarios (2)-(4) and return malicious
                                                # TODO: Check app version in case of update
                                                predictedLabel = 1
                                            else:
                                                # [PAPER] code(a*) == code(a): Assume scenarion (1) or maybe same developer making a simple adjustment (e.g., to resources)
                                                predictedLabel = 0
                                else:
                                    # [PAPER] compiler(a) == dexlib and compiler(a*) == dx/dexmerge: Defer to classifier
                                    predictedLabel = -1

                            else:
                                # [PAPER] compiler(a*) == dexlib
                                if matched_compiler.find("dx") != -1:
                                    # [PAPER] if compiler(a*) == dexlib and compiler(a) == dx/dexmerge
                                    # [PAPER] Scenario(s): (1) App (a*) is a malicious repackaged version of app (a)
                                    # [PAPER} ............ (2) app (a*) is the same benign app with a lazy developer editing something
                                    prettyPrint("Comparing the source code of \"%s\" and \"%s\"" % (app, matched_app), "debug")
                                    codeDiff = diffAppCode(app, matched_app, True) # Run in fast mode (any difference, return True)
                                    if len(codeDiff) == 0:
                                        # An exception has occurred = defer to classifier
                                        predictedLabel = -1
                                    else:
                                        if codeDiff["differences"] == True:
                                            # [PAPER] Original code is in "dx", repackaged in "dexlib", code is different = repackaged
                                            predictedLabel = 1
                                        else:
                                            # [PAPER] code(a*) == code(a): lazy developer scenario
                                            predictedLabel = 0
                                else:
                                    # [PAPER] compiler(a*) == compiler(a) == dexlib
                                    # [PAPER] Same app? Let us check the code
                                    prettyPrint("Comparing the source code of \"%s\" and \"%s\"" % (app, matched_app), "debug")
                                    codeDiff = diffAppCode(app, matched_app, True) # Run in fast mode (any difference, return True)
                                    if len(codeDiff) == 0:
                                        # An exception has occurred = defer to classifier
                                        predictedLabel = -1
                                    else:
                                        if codeDiff["differences"] == True:
                                            # [PAPER] compiler(a*) == compiler(a) == dexlib ^ code(a*) != code(a): defer to classifier 
                                            predictedLabel = -1
                                        else:
                                            # [PAPER] compiler(a*) == compiler(a) == dexlib ^ code(a*) == code(a): assume same benign app
                                            predictedLabel = 0

                            # Keep track of matched app and register matching technique for statistical purposes
                            matched_with = target_key 
                            prediction_method = "quick_matching"
             
            if predictedLabel == -1:
                # Could not match using quick matching
                ###################################
                # 2. Probabilistic classification #
                ###################################
                prettyPrint("Could not match app. Classifying using Multinomial naive Bayes")
                if os.path.exists(app.replace(".apk", ".static")):
                    app_static_features = eval(open(app.replace(".apk", ".static")).read())
                else:
                    prettyPrint("Could not find pre-extracted static features for app \"%s\". Extracting" % app, "debug")
                    app_static_features = extractStaticFeatures(app, preAPK=apk, preDEX=dex, preVM=vm)[-1]

                classes = clf.predict_proba(app_static_features).tolist()[0]
                prettyPrint("App \"%s\" classified as benign with P(C=0.0|app)=\"%s\" and as malicious with P(C=1.0|app)=\"%s\" " % (app, classes[0], classes[1]), "output")
                if max(classes) >= arguments.classthreshold:
                    predictedLabel = classes.index(max(classes))
                    prediction_method = "classification"
                    #matched_with = "n/a"
                
            if predictedLabel == -1:
                # Could not classify with confidence using naive Bayes
                ########################
                # 3. Try deep matching #
                ########################
                prettyPrint("Classification also did not work. Trying deep matching")
                matchings = matchAPKs(app, arguments.infodir, matchingDepth=arguments.matchingdepth, matchWith=10, matchingThreshold=arguments.matchingthreshold)
                prettyPrint("Successfully matched app \"%s\" with %s apps using threshold %s" % (app, len(matchings), arguments.matchingthreshold))
                malicious = 0
                for m in matchings:
                    color = "error" if matchings[m][1] == 1 else "debug"
                    prettyPrint("Matched with \"%s\" with similarity %s" % (m, matchings[m][0]), color)
                    if matchings[m] == 1:
                        malicious += 1

                predictedLabel = 1 if malicious >= len(matchings)/2 else 0
                prediction_method = "deep_matching"
                matched_with = "%s apps" % len(matchings)

            # Append results to lists
            predicted.append(predictedLabel)
            end_time = time.time() # End timing classification here
            prettyPrint("%s app \"%s\" classified as %s" % (labels[originalLabel], app[app.rfind('/')+1:], labels[predictedLabel]), "info2")
            # Add record to performance
            #compiler = compiler if prediction_method == "quick_matching" else "n/a"
            #matched_with = target_key if prediction_method == "quick_matching" else "n/a"
               
            if prediction_method == "classification":
                prediction_confidence = max(classes)
            else:
                prediction_confidence = 1.0
            performance[app] = (app_info["package"], compiler, end_time-start_time, originalLabel, predictedLabel, prediction_confidence, prediction_method, matched_with) 
            # (package_name, compiler, analysis time, original_label, predicted_label, prediction_confidence, prediction_method, matched_path)
  
        metrics_all = calculateMetrics(y, predicted)
        prettyPrint("Accuracy: %s" % metrics_all["accuracy"], "output")
        prettyPrint("Precision: %s" % metrics_all["precision"], "output")
        prettyPrint("Recall: %s" % metrics_all["recall"], "output")
        prettyPrint("Specificity: %s" % metrics_all["specificity"], "output")
        prettyPrint("F1 Score: %s" % metrics_all["f1score"], "output")
        # Save gathered performance metrics
        open("Dejavu_results_%s_%s_%s.txt" % (arguments.experimentlabel.replace(' ', '_'), arguments.matchingdepth, arguments.matchingthreshold), "w").write(str(performance))
        # Cleaning up?
         
        if arguments.cleanup == "yes":
            prettyPrint("Cleaning up")
            for directory in glob.glob("%s/tmp_*" % arguments.inputdir):
                shutil.rmtree(directory)

    except Exception as e:
        prettyPrintError("Error occurred: %s" % e)
        return False

    prettyPrint("Auf Wiedersehen")
    return True

if __name__ == "__main__":
    main()
