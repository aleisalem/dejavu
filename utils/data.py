#!/usr/bin/python

from dejavu.utils.graphics import *
from dejavu.utils.data import *
from dejavu.utils.misc import *
from dejavu.utils.db import *
from dejavu.conf.config import *
import os, random, subprocess, pickle
import numpy
from androguard.misc import *


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

def extractAPKInfo(targetAPK, infoLevel=1):
    """
    Statically analyzes APK and extracts information from it
    :param targetAPK: The path to the APK to analyze
    :type targetAPK: str
    :param infoLevel: The depth of information to retrieve (e.g., names, components, classes, etc.)
    :type infoLevel: int
    :return: A dict containing necessary information
    """
    try:
        apkData = {}
        apk, dex, vm = AnalyzeAPK(app)
        apkData["name"] = apk.get_app_name()
        apkData["package"] = apk.get_package()
        apkData["icon"] = apk.get_app_icon()
        apkData["signature"] = apk.get_signature()
        if infoLevel >= 2:
            apkData["activities"] = apk.get_activities()
            apkData["permissions"] = apk.get_permissions()
            apkData["providers"] = apk.get_providers()
            apkData["receivers"] = apk.get_receivers()
            apkData["services"] = apk.get_services()
            apkData["files"] = apk.get_files()
            subprocess.call(["apktool", "d", targetAPK])
            if not os.path.isdir(targetAPK.replace(".apk", "")):
                prettyPrint("Could not disassemble app", "warning")
            else:
               if not os.path.exists(apkData["icon"]):
                   prettyPrint("Could not find icon")

        if infoLevel >= 3:
            apkData["libraries"] = [l for l in apk.get_libraries()]
            apkData["classes"] = dex.get_classes_names()
            apkData["methods"] = []
            for c in apkData["classes"]:
                for m in dex.get_methods_class(c):
                    apkData["methods"].append("%s->%s" % (c, m.name))
        if infoLevel >= 4:
            apkData["callgraph"] = vm.get_call_graph()

    except Exception as e:
        prettyPrintError(e)
        return {}

    return apkData


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

def matchAPKs(source, target, matchingDepth=1):
    """
    Compares and attempts to match two APK's and returns a similarity measure
    :param source: The path to the source APK
    :type source: str
    :param target: The path to the target APK
    :type target: str
    :param matchingDepth: The depth and rigorosity of the matching (between 1 and 4)
    :type matchingDepth: int
    :return: A float depicting the similarity percentage between source and target APK's
    """
    try:
        similarity = 0.0

    except Exception as e:
        prettyPrintError(e)
        return 0.0

    return similarity



    """


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
