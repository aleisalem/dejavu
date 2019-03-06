#!/usr/bin/python

from dejavu.conf.config import *
from dejavu.utils.graphics import *
from dejavu.utils.data import *
from dejavu.utils.apkid import *
from dejavu.learning.feature_extraction import *
from dejavu.learning.scikit_learners import *
from dejavu.learning.hmm_learner import *
import pickle
from Levenshtein import distance
import ghmm
import argparse, os, glob, random, sys, operator, logging, shutil, time, signal
from exceptions import KeyError

def defineArguments():
    parser = argparse.ArgumentParser(prog="dejavu_tool_solo.py", description="Runs experiments using different labeling schemes on individual techniques")
    parser.add_argument("-n", "--technique", help="The technique to use in this experiment", required=True, choices=["quick_matching", "prob_classifier", "dynamic_matching", "hmm"])
    parser.add_argument("-x", "--inputdir", help="The directory containing the APKs", required=True)
    parser.add_argument("-i", "--infodir", help="The directory containing the pre-extracted app info used for APK matching", required=True)
    parser.add_argument("-a", "--apkdir", help="The directory containing the APK's of the benign apps", required=True)
    parser.add_argument("-l", "--experimentlabel", help="Give a label to the experiment currently run by the tool", required=False, default="Dejavu experiment")
    parser.add_argument("-y", "--experimenttype", help="Whether the experiment is performed on malicious or benign datasets", required=False, default="malicious", choices=["malicious", "benign"])
    parser.add_argument("-b", "--labeling", help="The type of labeling scheme to employ in deeming apps as [malicious-benign]", required=False, default="vt1-vt1", choices=["old", "vt1-vt1", "vt50p-vt50p", "vt50p-vt1"])
    parser.add_argument("-s", "--hustleup", help="Whether to use lookup structs to speed up the experiments", required=False, default="yes", choices=["yes", "no"])
    parser.add_argument("-u", "--cleanup", help="Whether to remove the directories containing data about the analyzed and tested apps", required=False, default="no", choices=["yes", "no"])
    parser.add_argument("-c", "--classifier", help="The path to the classifier to train as part of the \"prob_classifier\" mode", required=False)
    parser.add_argument("-r", "--clusters", help="The path to the file containing the benign apps clusters used by \"quick_matching\"", required=False)
    parser.add_argument("-m", "--comparetraces", help="Whether to compare droidmon logs or rely on VirusTotal info to label apps as part of \"dynamic_matching\"", required=False, default="yes", choices=["yes", "no"])
    parser.add_argument("-t", "--thresholds", help="The thresholds used during the experiments, depicts: (1) percentage beyond which apps are considered similar, and (2) the classification confidence (percentage) used by naive Bayes classifiers to assign apps to classes", type=float, required=False, default=0.80)
    parser.add_argument("-o", "--hmmthreshold", help="The negative threshold to be used by HMM in classifying apps", required=False, default=-250, type=int)
    parser.add_argument("-q", "--hmmlength", help="The maximum length of the trace to consider for classification using HMM", required=False, default=100, type=int)
    parser.add_argument("-z", "--includeargs", help="Whether to include method arguments in the loaded traces for \"dynamic_matching\" and \"hmm\"", required=False, default="yes", choices=["yes", "no"])
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

        # Prepare HMM data 
        if arguments.technique == "hmm":
            prettyPrint("Loading traces and actions from \"droidmon\" logs", "debug")
            if arguments.hustleup == "yes":
                a = "withargs" if arguments.includeargs == "yes" else "noargs"
                l = arguments.labeling if arguments.labeling == "old" else arguments.labeling[:arguments.labeling.find("-")]
                if os.path.exists("%s/dejavu_droidmon_traces_%s_%s.txt" % (LOOKUP_STRUCTS, l, a)):
                    prettyPrint("Loading traces from \"%s/dejavu_droidmon_traces_%s_%s.txt\"" % (LOOKUP_STRUCTS, l, a), "debug")
                    benignTraces = [t[1] for t in eval(open("%s/dejavu_droidmon_traces_%s_%s.txt" % (LOOKUP_STRUCTS, l, a)).read()) if len(t[1]) > 0] # Zero-length traces cause Segmentation Fault
                    if os.path.exists("%s/dejavu_droidmon_actions_%s_%s.txt" % (LOOKUP_STRUCTS, l, a)):
                        allActions = eval(open("%s/dejavu_droidmon_actions_%s_%s.txt" % (LOOKUP_STRUCTS, l, a)).read())
                    else:
                        allActions = []
                        prettyPrint("Retrieving all actions", "debug")
                        for trace in benignTraces:
                            for action in trace:
                                if not action in allActions:
                                    allActions.append(action)
            else:
                benignTraces, allActions = prepareHMMData(includeArguments=arguments.includeargs, labeling=arguments.labeling)

            # Train model
            prettyPrint("Training a HMM using %s traces and %s actions" % (len(benignTraces), len(allActions)))
            Pi = [1.0, 0.0]
            A = [[0.5, 0.5], [0.5, 0.5]]
            B = numpy.random.random((2, len(allActions))).tolist()
            prettyPrint("Building the hidden Markov model")
            hmm = HiddenMarkovModel(A, B, Pi, allActions)
            prettyPrint("Training the model")
            hmm.trainModel(benignTraces)                

        # Load classifier
        if arguments.technique == "prob_classifier":
            prettyPrint("Loading the classifier under \"%s\"" % arguments.classifier)
            clf = pickle.loads(open(arguments.classifier).read())

        # Load necessary lookup structures
        if arguments.technique == "quick_matching":
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
                            apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=1)               
                            if not apk or not dex or not vm:
                                prettyPrint("Could not analyze app. Skipping", "warning")
                                continue
                    else:
                        apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=1)
                        if not apk or not dex or not vm:
                            prettyPrint("Could not analyze app. Skipping", "warning")
                            continue
                else:
                    apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=1)
                    if not apk or not dex or not vm:
                        prettyPrint("Could not analyze app. Skipping", "warning")
                        continue    
            else:
                apk, dex, vm, app_info = extractAPKInfo(app, infoLevel=1)
                if not apk or not dex or not vm:
                    prettyPrint("Could not analyze app. Skipping", "warning")
                    continue
              
            #####################
            # 1. Quick matching #
            #####################
            if arguments.technique == "quick_matching":
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
                        if score >= arguments.thresholds:
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
                            if similarity >= arguments.thresholds:
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
                    counter += 1
                    continue


             
            elif arguments.technique == "prob_classifier":
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
                    counter += 1
                    continue 

                classes = clf.predict_proba(app_static_features).tolist()[0]
                prettyPrint("App \"%s\" classified as benign with P(C=0.0|app)=\"%s\" and as malicious with P(C=1.0|app)=\"%s\" " % (app, classes[0], classes[1]), "output")
                if max(classes) >= arguments.thresholds:
                    predictedLabel = classes.index(max(classes))
                else:
                    prettyPrint("Probabilistic classification could not classify app. Skipping", "warning")
                    counter += 1
                    continue

                prediction_method = "classification"
                prediction_confidence = max(classes)
                
            elif arguments.technique == "dynamic_matching":
                # Could not classify with confidence using naive Bayes
                ###########################
                # 3. Try dynamic matching #
                ###########################
                prettyPrint("Commencing dynamic matching")
                compareTraces = True if arguments.comparetraces == "yes" else False
                matchings = matchTrace(app, compareTraces=compareTraces, includeArguments=arguments.includeargs, labeling=arguments.labeling)
                prettyPrint("Successfully matched app \"%s\" with %s apps" % (app, len(matchings)))
                malicious = 0
                if len(matchings) > 0:
                    # [('sha256_hash', (0.575, 0)), .... ]
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
                prediction_method = "dynamic_matching"
                prediction_confidence = len(matchings)/2.0
                matched_with = "(%s)" % ",".join([x[0] for x in matchings])

            elif arguments.technique == "hmm":
                #####################################
                # 4. HMM-based trace classification #
                #####################################
                # Classify test app
                prettyPrint("Classifying test app with HMM")
                # 1. Retrieve its trace from repo
                app_key = app[app.rfind("/")+1:].replace(".apk", "")
                if len(glob.glob("%s/%s*.filtered" % (LOGS_DIR, app_key))) < 1:
                    prettyPrint("Could not find a \"droidmon\" log for app \"%s\". Skipping" % app, "warning")
                    counter += 1
                    continue

                testLogs = glob.glob("%s/%s*.filtered" % (LOGS_DIR, app_key))
                testLabels = []
                avgLikelihood = 0.0
                for log in testLogs:
                    includeArgs = True if arguments.includeargs == "yes" else False
                    testTrace = parseDroidmonLog(log, includeArguments=includeArgs)
                    testTrace = testTrace[:arguments.hmmlength] if len(testTrace) > arguments.hmmlength else testTrace
                    # 2. Remove actions not in all actions (i.e., synchronize traces)
                    tmpSequence = []
                    for index in range(len(testTrace)):
                        if testTrace[index] in allActions:
                            tmpSequence.append(testTrace[index])

                    if len(tmpSequence) < 1:
                        prettyPrint("Trace length is zero after synchronization. Skipping", "warning")
                        continue
                    # 3. Classify the trace
                    sequence = ghmm.EmissionSequence(hmm.sigma, tmpSequence)
                    # Calculating the log likelihood for that trace
                    logLikelihood = hmm.ghmmModel.loglikelihood(sequence)
                    prettyPrint("log P(O|lambda)=%s" % logLikelihood, "debug")
                    prettyPrint("Classifying with a threshold of %s" % arguments.hmmthreshold)
                    avgLikelihood += logLikelihood 
                    if logLikelihood < arguments.hmmthreshold:
                        # The sequence is suspicious
                        testLabels.append(1)
                    else:
                        testLabels.append(0)

                if len(testLabels) < 1:
                    continue

                predictedLabel = 1 if sum(testLabels) / float(len(testLabels)) >= 0.5 else 0
                prediction_method = "hmm"
                prediction_confidence = avgLikelihood / float(len(testLabels))
                matched_with = "N/A"

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
                prettyPrint("%s app \"%s\" classified as %s" % (labels[int(originalLabel)], app[app.rfind('/')+1:], labels[int(predictedLabel)]), "info2")
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
                # (package_name, compiler, analysis time, original_label, predicted_label, prediction_confidence, prediction_method, matched_with)
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
        if arguments.technique == "quick_matching":
            fileName = "Dejavu_results_solo_quick_matching_%s_%s_%s.txt" % (arguments.experimentlabel, arguments.labeling, arguments.thresholds)
            prettyPrint("Random labels: %s out of %s" % (len(randomLabels), len(y)), "output")
        elif arguments.technique == "prob_classifier":
            fileName = "Dejavu_results_prob_classifier_%s_%s_%s.txt" % (arguments.experimentlabel, arguments.labeling, arguments.thresholds)
        elif arguments.technique == "dynamic_matching":
            fileName = "Dejavu_results_dynamic_matching_%s_%s_%s_%s.txt" % (arguments.experimentlabel, arguments.labeling, arguments.comparetraces, arguments.includeargs)
        elif arguments.technique == "hmm":
            fileName = "Dejavu_results_hmm_%s_%s_%s_%s_%sargs.txt" % (arguments.experimentlabel, arguments.labeling, arguments.hmmthreshold, arguments.hmmlength, arguments.includeargs)

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
