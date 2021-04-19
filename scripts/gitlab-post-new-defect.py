#!/usr/bin/python

import json
import sys
import os
import argparse
import urllib
import glob

# Parse command line arguments
parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,
        description='Post Coverity issue summary to GitLab CI Notes Object')
parser.add_argument('--debug', default=0, help='set debug level [0-9]')
parser.add_argument('mergeKeys', nargs=argparse.REMAINDER)
args = parser.parse_args()

debug = int(args.debug)
mergeKeys = args.mergeKeys

# Populate a map with the merge keys we want
mergeKeysToMatch = dict()
for mergeKey in mergeKeys:
    print "Match Merge Key: " + mergeKey
    mergeKeysToMatch[mergeKey] = 1

jsonFiles = glob.glob("./.synopsys/polaris/diagnostics/analyze,*/local-analysis/results/incremental-results.json")
#jsonFiles = glob.glob("./incremental-results.json")
jsonFile = jsonFiles[0]

# Process output from Polaris CLI
with open(jsonFile) as f:
  data = json.load(f)

print "Reading incremental analysis results from " + jsonFile
if(debug): print "DEBUG: " + json.dumps(data, indent = 4, sort_keys=True) + "\n"

# Loop through found issues for specified merge keys, and build out output map
# TODO: Can there be multiple entries for the merge key? I think the right thing would be to list all of them.

sast_report = dict()
sast_report["version"] = "2.0"
vulnerabilities = []

for item in data["issues"]:
    checkerName = item["checkerName"]
    checkerProperties = item["checkerProperties"]
    subcategoryShortDescription = checkerProperties["subcategoryShortDescription"]
    subcategoryLongDescription = checkerProperties["subcategoryLongDescription"]
    cwe = checkerProperties["cweCategory"]
    impact = checkerProperties["impact"]
    codeLangauge = item["code-language"]
    mergeKey = item["mergeKey"]
    strippedMainEventFilePathname = item["strippedMainEventFilePathname"]
    mainEventLineNumber = item["mainEventLineNumber"]

    eventNumber = 1
    if mergeKey in mergeKeysToMatch:
      print "Foud merge key " + mergeKey + "\n"
      newIssue = dict()
      newIssue["id"] = mergeKey
      newIssue["category"] = "sast"
      newIssue["name"] = subcategoryShortDescription
      newIssue["message"] = subcategoryShortDescription
      newIssue["description"] = subcategoryLongDescription
      newIssue["severity"] = impact
      newIssue["confidence"] = "Medium" # TODO: Something else
      scanner = dict()
      scanner["id"] = "synopsys_coverity";
      scanner["name"] = "Synopsys Coverity";
      newIssue["scanner"] = scanner;
      location = dict();

      for event in item["events"]:
        if event["main"]:
          location["file"] = event["strippedFilePathname"]
          location["start_line"] = event["lineNumber"]
          location["end_line"] = event["lineNumber"]
          # TODO: Break class and method into two pieces
          location["class"] = item["functionDisplayName"]
          location["method"] = item["functionDisplayName"]

          newIssue["description"] = newIssue["description"] + "" + event["eventDescription"]

        if event["remediation"]:
          newIssue["description"] = newIssue["description"] + "\n\n" + event["eventDescription"]

      newIssue["location"] = location

      identifiers = []
      identifiers_snps = dict()
      identifiers_snps["type"] = "synopsys_coverity_type"
      identifiers_snps["name"] = "Synopsys Coverity-" + checkerName
      identifiers_snps["value"] = checkerName
      identifiers_snps["url"] = "http://www.synopsys.com/..."
      identifiers.append(identifiers_snps)
      identifiers_cwe = dict()
      identifiers_cwe["type"] = "cwe"
      identifiers_snps["name"] = "CWE-" + cwe
      identifiers_snps["value"] = cwe
      identifiers_snps["url"] = "https://cwe.mitre.org/data/definitions/" + cwe + ".html"
      identifiers.append(identifiers_cwe)

      newIssue["identifiers"] = identifiers

      #print newIssue
      vulnerabilities.append(newIssue)

sast_report["vulnerabilities"] = vulnerabilities

with open('synopsys-gitlab-sast.json', 'w') as fp:
  json.dump(sast_report, fp, indent=4)
