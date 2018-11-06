#!/usr/bin/python

from dejavu.conf.config import *
from dejavu.utils.graphics import *
from dejavu.utils.misc import *
import os, random, subprocess, pickle, zipfile, shutil, json, exceptions, time
import numpy
from androguard.misc import *
import networkx as nx
from skimage.measure import compare_ssim
import imutils
import cv2

def simCertificateIssuers(issuerA, issuerB):
    """
    Compares the issuers of two certificates
    :param issuerA: The issuer details of the first certificate
    :type issuerA: str
    :param issuerB: The issuer details of the second certificate
    :type issuerB: str
    :return: float depicting the similarity between the two issuers
    """
    try:
        # Parse two strings to extract data
        dataA, dataB = {}, {}
        delimiterA = ';' if issuerA.find('; ') != -1 else ','
        delimiterB = ';' if issuerB.find('; ') != -1 else ','
        for t in issuerA.split("%s " % delimiterA):
            if len(t) > 0:
                key, value = t.split(": ")
                dataA[key] = value

        for t in issuerB.split("%s " % delimiterB):
            if len(t) > 0:
                key, value = t.split(": ")
                dataB[key] = value

        # Gather common keys
        commonKeys = list(set.intersection(set(dataA.keys()), set(dataB.keys())))
        sims = []
        for key in commonKeys:
            sims.append(stringRatio(dataA[key], dataB[key]))
            
    except Exception as e:
        prettyPrintError(e)
        return 0.0
    
    sim = 0.0 if len(sims) < 1 else sum(sims)/float(len(sims))

    return sim

def simImages(imgA, imgB):
    """
    Compares the structure similarity of two images and retrurns the SSIM similarity
    :param imgA: The path to the first image
    :type imgA: str
    :param imgB: The path to the second image
    :type imgB: str
    :return: float depicting the SSIM similarity between the two images
    """
    try:
        # load the two input images
        imageA = cv2.imread(imgA)
        imageB = cv2.imread(imgB)
        score = -1.0
 
        # convert the images to grayscale
        grayA = cv2.cvtColor(imageA, cv2.COLOR_BGR2GRAY)
        grayB = cv2.cvtColor(imageB, cv2.COLOR_BGR2GRAY)

        # resize images in case of mismatching dimensions
        # resize smaller images to bigger ones
        if grayA.shape > grayB.shape:
            grayB.resize(grayA.size)
            grayA.resize(grayA.size)

        elif grayA.shape < grayB.shape:
            grayA.resize(grayB.size)
            grayB.resize(grayB.size)

        # compute the Structural Similarity Index (SSIM) between the two
        # images, ensuring that the difference image is returned
        (score, sim) = compare_ssim(grayA, grayB, full=True)
        sim = (sim * 255).astype("uint8")
        
        #print("SSIM: {}".format(score))
    except Exception as e:
        prettyPrintError(e)
        return 0.0      

    return score

def diffTraces(traceX, traceY, ignoreArguments=True):
    """
    Diffs two traces and returns the number of differences
    :param traceX: The first trace
    :type traceX: list of str
    :param traceY: The second trace
    :type traceY: list of str
    :param ignoreArguments: Whether to consider the method arguments in the comparisons
    :type ignoreArguments: bool
    :return: An int depicting the number of differences between the two traces
    """
    try:
        diffs = abs(len(traceX)-len(traceY))
        upperbound = len(traceX) if len(traceX) <= len(traceY) else len(traceY)
        for index in range(upperbound):
             callX = traceX[index] if not ignoreArguments else traceX[index][:traceX[index].find("(")]
             callY = traceY[index] if not ignoreArguments else traceY[index][:traceY[index].find("(")]
             if callX != callY:
                 diffs += 1

    except Exception as e:
        prettyPrintError(e)
        return -1

    return diffs

def diffAppCode(app1, app2):
    """
    Diffs (app1-app2) the source code of two Android apps
    :param app1: The path to the app to which new code is presumed to be added (e.g., repackaged malware)
    :type app1: str
    :param app2: The path to the app used as reference point
    :type app2: str
    :return: A dict including different classes and the different code in them
    """
    try:
        prettyPrint("Analyzing apps")
        apk1, dex1, vm1 = AnalyzeAPK(app1)
        apk2, dex2, vm2 = AnalyzeAPK(app2)
        dex1, dex2 = dex1[0], dex2[0]
        # Start diffing
        diff = {}
        # 1.1. Retrieve newly-added classes
        new_classes = list(set(dex1.get_classes_names()).difference(dex2.get_classes_names()))
        prettyPrint("Adding %s newly-added classes to difference" % len(new_classes)) 
        # 1.2. Add code to diff dictionary
        for new_class in new_classes:
            c = dex1.get_class(new_class)
            diff[new_class] = c.get_source()
        # Diff existing classes
        old_classes = list(set(dex1.get_classes_names()).intersection(set(dex2.get_classes_names())))
        prettyPrint("Checking %s common classes" % len(old_classes))
        for old_class in old_classes:
            source1, source2 = dex1.get_class(old_class).get_source(), dex2.get_class(old_class).get_source()
            if hashlib.sha1(source1).hexdigest() != hashlib.sha1(source2).hexdigest():
                prettyPrint("Class \"%s\" is different. Retrieving differences" % old_class, "debug")
                new_code = str(set(source1.split("\n")).difference(set(source2.split("\n"))))
                diff[old_class] = new_code
    
        # Add the packaged names 
        diff["piggybacked"], diff["original"] = apk1.get_package(), apk2.get_package()

    except Exception as e:
        prettyPrintError(e)
        return {}

    return diff


def extractAPKInfo(targetAPK, infoLevel=1, saveInfo=True):
    """
    Statically analyzes APK and extracts information from it
    :param targetAPK: The path to the APK to analyze
    :type targetAPK: str
    :param infoLevel: The depth of information to retrieve (e.g., names, components, classes, etc.)
    :type infoLevel: int
    :param saveInfo: Whether to save the extracted information to file
    :type saveInfo: boolean
    :return: A tuple of the three objects retrurned by androguard and a dict containing necessary information
    """
    try:
        apkData = {}
        prettyPrint("Analyzing target APK \"%s\"" % targetAPK)
        apk, dex, vm = AnalyzeAPK(targetAPK)
        dex = dex[0] if type(dex) == list else dex
        apkData["name"] = apk.get_app_name()
        apkData["package"] = apk.get_package()
        apkData["icon"] = apk.get_app_icon()
        #apkData["signature"] = apk.get_signature()
        #apkData["certificate"] = apk.get_certificate(apk.get_signature_name())
        apkData["issuer"] = apk.get_certificate(apk.get_signature_name()).issuer.human_friendly
        with zipfile.ZipFile(targetAPK, "r") as zip_ref:
            try:
                destination = "%s/tmp_%s/" % (targetAPK[:targetAPK.rfind('/')], apkData["package"])
                zip_ref.extractall(destination)
                zip_ref.close()
            except zipfile.BadZipfile as e:
                prettyPrint("Could not retrieve the app's icon", "warning") 

        if infoLevel >= 2:
            apkData["activities"] = apk.get_activities()
            apkData["permissions"] = apk.get_permissions()
            apkData["providers"] = apk.get_providers()
            apkData["receivers"] = apk.get_receivers()
            apkData["services"] = apk.get_services()
            apkData["files"] = apk.get_files()
            
        if infoLevel >= 3:
            apkData["libraries"] = [l for l in apk.get_libraries()]
            apkData["classes"] = dex.get_classes_names()
            apkData["methods"] = []
            for c in apkData["classes"]:
                for m in dex.get_methods_class(c):
                    apkData["methods"].append("%s->%s" % (c, m.name))
        if infoLevel >= 4:
            callgraph = vm.get_call_graph()
            apkData["callgraph"] = "%s/call_graph.gpickle" % destination

        if saveInfo:
            prettyPrint("Saving extracted info to \"%s\"" % destination, "debug") 
            if not os.path.exists(destination):
                prettyPrint("Could not find the temporary directory \"%s\". Saving aborted"  % destination, "warning")
                return apk, dex, vm, apkData
            else:
                open("%s/data.txt" % destination, "w").write(str(apkData))
                if infoLevel >= 4:
                    nx.write_gpickle(callgraph, "%s/call_graph.gpickle" % destination)

    except exceptions.RuntimeError as re:
        prettyPrintError(re)
        
    except Exception as e:
        prettyPrintError(e)
        return None, None, None, {}

    return apk, dex, vm, apkData

def hex_to_rgb(value):
    value = value.lstrip('#')
    lv = len(value)
    return tuple(int(value[i:i+lv/3], 16) for i in range(0, lv, lv/3))

def rgb_to_hex(rgb):
    return '%02x%02x%02x' % rgb

def injectBehaviorInTrace(targetTrace, insertionProbability, multipleBehaviors=False):
    """
    Injects malicious blocks of pre-defined malicious behaviors into a target trace with a the likelihood of [insertionProbability]
    :param targetTrace: The trace to inject the behaviors in
    :type targetTrace: list
    :param insertionProbability: The probability with which behaviors are injected into the target trace
    :type insertionProbability: float
    :param multipleBehaviors: Whether to inject different behaviors in the same target trace
    :type multipleBehaviors: bool
    :return: A list depicting the new trace with the inserted behavior(s)
    """
    try:
        newTrace = []
        # Retrieve store behaviors
        behaviors = loadMaliciousBehaviors()
        # Iterate over the target trace and inject the malicious behaviors
        constantBehavior = behaviors[random.randint(0, len(behaviors)-1)] if not multipleBehaviors else ""
        currentIndex = 0
        # Find insertion points and behaviors
        positions = []
        while currentIndex < len(targetTrace):
            if flip(insertionProbability) == "YES":
                b = constantBehavior if constantBehavior != "" else behaviors[random.randint(0, len(behaviors)-1)]
                # Insert behavior
                positions.append((currentIndex+1, b))
                # Update current index
                currentIndex = currentIndex + len(b) + 1
        # Insert behaviors in positions
        print positions
        newTrace = [] + targetTrace
        if len(positions) > 0:
            for p in positions:
                before = newTrace[:p[0]]
                after = newTrace[p[0]:]
                middle = ["%s()" % i for i in p[1]]
                before.extend(middle)
                newTrace = before+after
                
    except Exception as e:
        prettyPrintError(e)
        return []

    return newTrace

def loadNumericalFeatures(featuresFile, delimiter=","):
    """
    Loads numerical features from a file and returns a list

    :param featuresFile: The file containing the feature vector
    :type featuresFile: str
    :param delimiter: The character separating numerical features
    :type delimiter: str    
    """
    try:
        if not os.path.exists(featuresFile):
            prettyPrint("Unable to find the features file \"%s\"" % featuresFile, "warning")
            return []
        content = open(featuresFile).read()
        if content.lower().find("[") != -1 and content.lower().find("]") != -1:
            features = eval(content)
        else:
            features = [float(f) for f in content.replace(' ','').split(delimiter)]

    except Exception as e:
        prettyPrintError(e)
        return []

    return features

def loadMaliciousBehaviors():
    """
    Loads malicious behaviors from the database
    return: A list of malicious behaviors stored in the database
    """
    try:
        dejavuDB = DB()
        cursor = dejavuDB.select([], "behaviors")
        behaviors = cursor.fetchall()
        if len(behaviors) < 1:
            prettyPrint("Could not retrieve malicious behaviors from the database. Inserting behaviors in \"%s\"" % MALICIOUS_BEHAVIORS, "warning")
        content = open(MALICIOUS_BEHAVIORS).read().split('\n')
        if len(content) < 1:
             prettyPrint("Could not retrieve any behaviors from \"%s\"" % MALCIOUS_BEHAVIORS, "error")
             return []
        for line in content:
            if len(line) > 1:
                desc = line.split(':')[0]
                sequence = line.split(':')[1].replace(' ','')
                timestamp = getTimeStamp(includeDate=True)
                dejavuDB.insert("behaviors", ["bDesc", "bSequence", "bTimestamp"], [desc, sequence, timestamp])
        # Lazy guarantee of same data format
        cursor = dejavuDB.select([], "behaviors")
        behaviors = cursor.fetchall()

    except Exception as e:
        prettyPrintError(e)
        return []

    return behaviors

def logEvent(msg):
    try:
        open(LOG_FILE, "w+").write(msg)

    except Exception as e:
        prettyPrintError(e)
        return False

    return True 

def matchAPKs(sourceAPK, targetAPKs, matchingDepth=1, matchingThreshold=0.5, matchWith=1, useSimiDroid=False, fastSearch=True, matchingTimeout=300):
    """
    Compares and attempts to match two APK's and returns a similarity measure
    :param sourceAPK: The path to the source APK (the original app you wish to match)
    :type sourceAPK: str
    :param targetAPK: The path to the directory containing target APKs (against which you wish to match)
    :type targetAPK: str
    :param matchingDepth: The depth and rigorosity of the matching (between 1 and 4)
    :type matchingDepth: int
    :param matchingThreshold: A similarity percentage above which apps are considered similar
    :type matchingThreshold: float
    :param matchWith: The number of matchings to return (default: 1)
    :type matchWith: int
    :param useSimiDroid: Whether to use SimiDroid to perform the comparison
    :type useSimiDroid: boolean
    :param fastSearch: Whether to return matchings one maximum number of matches [matchWith] is reached
    :type fastSearch: boolean
    :param matchingTimeout: The time (in seconds) to allow the matching process to continue
    :type matchingTimeoue: int
    :return: A list of str depicting the top [matchWith] apps similar to [sourceAPK] with more thatn [matchingThreshold] percetange
    """
    try:
        similarity = 0.0
        # Retrieve information from the source APK
        if not useSimiDroid:
            sourceInfo = extractAPKInfo(sourceAPK, matchingDepth)

        targetApps = glob.glob("%s/*" % targetAPKs) if useSimiDroid == False else glob.glob("%s/*.apk" % targetAPKs)
        if len(targetApps) < 1:
            prettyPrint("Could not retrieve any APK's or directories from \"%s\"" % targetApps, "error")
            return []
 
        prettyPrint("Successfully retrieved %s apps from \"%s\"" % (len(targetApps), targetAPKs))
        matchings = {}
        counter = 0
        startTime = time.time()
        for targetAPK in targetApps:
            counter += 1
            # Timeout?
            if counter >= matchingTimeout:
                prettyPrint("Matching timeout", "error")
                return matchings
            prettyPrint("Matching with \"%s\", #%s out of %s" % (targetAPK, counter, len(targetApps)), "debug")
            if useSimiDroid == False:
                # Use homemade recipe to perform the comparison
                if not os.path.exists("%s/data.txt" % targetAPK):
                    prettyPrint("Could not find a \"data.txt\" file for app \"%s\". Skipping" % targetAPK, "warning")
                    continue

                # Load pre-extracted target app information
                targetInfo = eval(open("%s/data.txt" % targetAPK).read())
                targetInfo["callgraph"] = nx.read_gpickle("%s/call_graph.gpickle" % targetAPK) if os.path.exists("%s/call_graph.gpickle" % targetAPK) and matchingDepth >= 4 else None
                targetLabel = eval(open("%s/label" % targetAPK).read())
  
                # Start the comparison
                differences = []
                if matchingDepth >= 1:
                    differences.append(stringRatio(sourceInfo["name"], targetInfo["name"]))
                    differences.append(stringRatio(sourceInfo["package"], targetInfo["package"]))
                    differences.append(stringRatio(sourceInfo["icon"], targetInfo["icon"]))
                    #differences.append(stringRatio(sourceInfo["signature"], targetInfo["signature"]))
                    #differences.append(stringRatio(sourceInfo["certificate"], targetInfo["certificate"]))
                    sourceIcon = "%s/tmp_%s/%s" % (sourceAPK[:sourceAPK.rfind("/")], sourceInfo["package"], sourceInfo["icon"]) if sourceInfo["icon"] is not None else ""
                    targetIcon = "%s/%s" % (targetAPK, targetInfo["icon"][targetInfo["icon"].rfind('/')+1:]) if targetInfo["icon"] is not None else ""
                    if os.path.exists(sourceIcon) and os.path.exists(targetIcon):
                        differences.append(diffImages(sourceIcon, targetIcon))
     
                if matchingDepth >= 2:
                    differences.append(listsRatio(sourceInfo["activities"], targetInfo["activities"]))
                    differences.append(listsRatio(sourceInfo["permissions"], targetInfo["permissions"]))
                    differences.append(listsRatio(sourceInfo["providers"], targetInfo["providers"]))
                    differences.append(listsRatio(sourceInfo["receivers"], targetInfo["receivers"]))
                    differences.append(listsRatio(sourceInfo["services"], targetInfo["services"]))
                    differences.append(listsRatio(sourceInfo["files"], targetInfo["files"]))

                if matchingDepth >= 3:
                    differences.append(listsRatio(sourceInfo["libraries"], targetInfo["libraries"]))
                    differences.append(listsRatio(sourceInfo["classes"], targetInfo["classes"]))
                    differences.append(listsRatio(sourceInfo["methods"], targetInfo["methods"]))

                if matchingDepth >= 4:
                    isomorphic = nx.algorithms.is_isomorphic(sourceInfo["callgraph"], targetInfo["callgraph"])
                    if isomorphic:
                        differences.append(1.0)
                    else:
                        differences.append(0.0)
            else:
                # Use SimiDroid to perform comparison
                curDir = os.path.abspath(".")
                os.chdir(SIMIDROID_DIR)
                cmd = "java -jar SimiDroid.jar %s %s" % (sourceAPK, targetAPK)
                outFile = "%s-%s.json" % (sourceAPK[sourceAPK.rfind('/')+1:].replace(".apk", ""), targetAPK[targetAPK.rfind("/")+1:].replace(".apk", ""))
                p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                p.communicate()
                if not os.path.exists(outFile):
                    prettyPrint("Could not find SimiDroid output file. Skipping", "warning")
                    continue
 
                outContent = json.loads(open(outFile).read())
                os.chdir(curDir)

            similarity = float(sum(differences))/float(len(differences)) if useSimiDroid == False else float(outContent["conclusion"]["simiScore"])
            prettyPrint("Similarity score: %s" % similarity)
            if similarity >= matchingThreshold:
                prettyPrint("Got a match between source \"%s\" and app \"%s\", with score %s" % (sourceAPK[sourceAPK.rfind("/")+1:].replace(".apk", ""), targetAPK[targetAPK.rfind("/")+1:].replace(".apk", ""), similarity), "output")

                if useSimiDroid == False:
                    matchings[targetInfo["package"]] = (similarity, targetLabel[0])
                else:
                    matchings[targetAPK] = (similarity, targetLabel[0])

                currentTime = time.time()
                if (fastSearch and len(matchings) >= matchWith) or (currentTime - startTime >= matchingTimeout):
                    # Return what we've got so far
                    if len(matchings) >= matchWith:
                        return sortDictByValue(matchings, True)[:matchWith]
                    else:
                        return sortDictByValue(matchings, True)

    except Exception as e:
        prettyPrintError(e)
        return []

    if len(matchings) >= matchWith:
        return sortDictByValue(matchings, True)[:matchWith]
    else:
        return sortDictByValue(matchings, True)


def matchTwoAPKs(sourceDir, targetDir, matchingDepth=1, useSimiDroid=False):
    """
    Compares and attempts to match two APK's and returns a similarity measure
    :param sourceDir: The path to the directory containing information pre-extracted from the source APK
    :type sourceDir: str
    :param targetDir: The path to the directory containing information pre-extracted from the target APK
    :type targetDir: str
    :param matchingDepth: The depth and rigorosity of the matching (between 1 and 4)
    :type matchingDepth: int
    :param useSimiDroid: Whether to use SimiDroid to perform the comparison
    :type useSimiDroid: boolean
    :return: A float depicting the degree of similarity between two apps
    """
    try:
        similarity = 0.0
        # Retrieve information from the source APK
        if useSimiDroid == False:
            if not os.path.exists("%s/data.txt" % sourceDir) or not os.path.exists("%s/data.txt" % targetDir):
                prettyPrint("Could not locate either the source or the target directories. Returning 0.0", "warning")
                return 0.0

            sourceInfo = eval(open("%s/data.txt" % sourceDir).read())
            sourceInfo["callgraph"] = nx.read_gpickle("%s/call_graph.gpickle" % sourceDir) if os.path.exists("%s/call_graph.gpickle" % sourceDir) and matchingDepth >= 4 else None
            targetInfo = eval(open("%s/data.txt" % targetDir).read())
            targetInfo["callgraph"] = nx.read_gpickle("%s/call_graph.gpickle" % targetDir) if os.path.exists("%s/call_graph.gpickle" % targetDir) and matchingDepth >= 4 else None
            # Another sanity check
            if len(sourceInfo) < 1 or len(targetInfo) < 1:
                prettyPrint("Could not retrieve info about either the source or the target apps. Returning 0.0", "warning")
                return 0.0

            # Start the comparison
            differences = []
            if matchingDepth >= 1:
                differences.append(stringRatio(sourceInfo["name"], targetInfo["name"]))
                differences.append(stringRatio(sourceInfo["package"], targetInfo["package"]))
                differences.append(stringRatio(sourceInfo["icon"], targetInfo["icon"]))
                #differences.append(stringRatio(sourceInfo["signature"], targetInfo["signature"]))
                sourceIcon = "%s/%s" % (sourceDir, sourceInfo["icon"]) if sourceInfo["icon"] is not None else ""
                targetIcon = "%s/%s" % (targetDir, targetInfo["icon"][targetInfo["icon"].rfind('/')+1:]) if targetInfo["icon"] is not None else ""
                if os.path.exists(sourceIcon) and os.path.exists(targetIcon):
                    differences.append(diffImages(sourceIcon, targetIcon))

            if matchingDepth >= 2:
                differences.append(listsRatio(sourceInfo["activities"], targetInfo["activities"]))
                differences.append(listsRatio(sourceInfo["permissions"], targetInfo["permissions"]))
                differences.append(listsRatio(sourceInfo["providers"], targetInfo["providers"]))
                differences.append(listsRatio(sourceInfo["receivers"], targetInfo["receivers"]))
                differences.append(listsRatio(sourceInfo["services"], targetInfo["services"]))
                differences.append(listsRatio(sourceInfo["files"], targetInfo["files"]))

            if matchingDepth >= 3:
                differences.append(listsRatio(sourceInfo["libraries"], targetInfo["libraries"]))
                differences.append(listsRatio(sourceInfo["classes"], targetInfo["classes"]))
                differences.append(listsRatio(sourceInfo["methods"], targetInfo["methods"]))

            if matchingDepth >= 4:
                isomorphic = nx.algorithms.is_isomorphic(sourceInfo["callgraph"], targetInfo["callgraph"])
                if isomorphic:
                    differences.append(1.0)
                else:
                    differences.append(0.0)

        else:
            # Use SimiDroid to perform comparison
            curDir = os.path.abspath(".")
            os.chdir(SIMIDROID_DIR)
            cmd = "java -jar SimiDroid.jar %s %s" % (sourceAPK, targetAPK)
            outFile = "%s-%s.json" % (sourceAPK[sourceAPK.rfind('/')+1:].replace(".apk", ""), targetAPK[targetAPK.rfind("/")+1:].replace(".apk", ""))
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
            p.communicate()
            if not os.path.exists(outFile):
                prettyPrint("Could not find SimiDroid output file. Skipping", "warning")
                return 0.0
 
            outContent = json.loads(open(outFile).read())
            os.chdir(curDir)
            
        # Calculate similarity
        similarity = float(sum(differences))/float(len(differences)) if useSimiDroid == False else float(outContent["conclusion"]["simiScore"])
        prettyPrint("Similarity score: %s" % similarity)

    except Exception as e:
        prettyPrintError(e)
        return 0.0

    return similarity

