"use strict";
// Copyright (c) 2021 Synopsys, Inc. All rights reserved worldwide.
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
Object.defineProperty(exports, "__esModule", { value: true });
var command_line_1 = require("./lib/command-line");
var sarifUtils = require("./lib/cov-format-sarif-utils");
var fs = require("fs");
var process = require("process");
var stream_1 = require("stream");
var JSONStream = require("JSONStream");
var defOpts = {
    help: null,
    checkoutPaths: {},
    githubUrl: 'https://github.com'
};
// An object which is guaranteed to have the same keys as CovFormatSarifForGithubOptions,
// but where those values map to values of type CmdLineSpec
var cmdLineSpec = {
    program: 'cov-format-sarif-for-github',
    summary: 'Convert Coverity Desktop JSON to SARIF for consumption by GitHub',
    examples: 'node cov-format-sarif-for-github --inputFile coverityResults.json --repoName myUser/myRepo --checkoutPath myUser/myRepo /myRepo/checkout/path 123456 --outputFile coverityResults.sarif',
    options: {
        help: {
            longSwitch: '--help',
            shortSwitch: '-h',
            numParams: 0,
            paramHelp: [],
            required: false,
            helpText: 'Display this help text and exit.',
            validators: []
        },
        inputFile: {
            longSwitch: '--inputFile',
            shortSwitch: '-i',
            numParams: 1,
            paramHelp: ['FILE'],
            required: true,
            helpText: 'The file to be processed. This file should be in the Coverity Desktop JSON format (version 7 or later).',
            validators: []
        },
        repoName: {
            longSwitch: '--repoName',
            shortSwitch: '-r',
            numParams: 1,
            paramHelp: ['USER/REPO'],
            required: true,
            helpText: 'The GitHub repository under analysis in the form USER/REPO.',
            validators: [validateRepo]
        },
        checkoutPaths: {
            longSwitch: '--checkoutPath',
            shortSwitch: '-c',
            numParams: 3,
            paramHelp: ['USER/REPO', 'PATH', 'COMMIT'],
            required: true,
            helpText: 'One or more checkout paths required for re-writing URIs to correct GitHub URLs.\n\tThree arguments must be passed to this flag:\n\t\t1) the GitHub repository name in USER/REPO format,\n\t\t2) the absolute path to the checked-out repository, and\n\t\t3) the commit of the repository when the analysis was performed.\n\tThis option must be specified at least once for the main repository under analysis as specified by --repoName, and may be specified additional times for repositories that the analysis depended on.',
            validators: [validatePaths]
        },
        outputFile: {
            longSwitch: '--outputFile',
            shortSwitch: '-o',
            numParams: 1,
            paramHelp: ['FILE'],
            required: true,
            helpText: 'The file to write the SARIF result to.',
            validators: []
        },
        githubUrl: {
            longSwitch: '--githubUrl',
            shortSwitch: '-g',
            numParams: 1,
            paramHelp: ['URL'],
            required: false,
            helpText: 'The URL used to when rewriting checkout paths to URLs. Defaults to ' +
                defOpts.githubUrl +
                ' but may be overridden (to an on premises GitHub deployment for example).',
            validators: []
        }
    }
};
// Form a GitHub URI from a local filepath. Resulting path is relative if the
// path is from the main repo. Use reportedPathsSet to report unmatched paths
// exactly once.
var reportedPathsSet = new Set();
function rewriteUriForGithub(filePath, _a) {
    var repoName = _a.repoName, checkoutPaths = _a.checkoutPaths, githubUrl = _a.githubUrl;
    var match = false;
    var retVal = filePath;
    for (var _i = 0, _b = Object.keys(checkoutPaths); _i < _b.length; _i++) {
        var repo = _b[_i];
        var _c = checkoutPaths[repo], checkoutPath = _c.checkoutPath, commit = _c.commit;
        // Trailing slashes are added to checkoutPath during command line
        // processing if one is not present
        if (filePath.startsWith(checkoutPath)) {
            // Remove the prefix
            var relPath = filePath.slice(checkoutPath.length);
            // We only want to remove prefixes that are separated by a path separator
            // (to prevent /check from being stripped from /checkout for example).
            // Since we strip trailing separators, we expect the first character
            // to be a separator
            if (relPath.charAt(0) !== '/' && relPath.charAt(0) !== '\\') {
                continue;
            }
            relPath = relPath.replace(/^[\\\/]+/, '');
            if (repo === repoName) {
                retVal = relPath;
            }
            else {
                retVal = githubUrl + "/" + repo + "/blob/" + commit + "/" + relPath;
            }
            match = true;
        }
    }
    if (!match && !reportedPathsSet.has(filePath)) {
        reportedPathsSet.add(filePath);
        console.log("No --checkoutPath option was specified that matches the file \"" + filePath + "\"");
    }
    return retVal;
}
function formatStepsMessage(start, end, treeStart, treeEnd) {
    if (start === end) {
        return "See details in step " + start + ". (Event #" + treeStart + ")";
    }
    else {
        return "See details in steps " + start + " - " + end + ". (Events #" + treeStart + " - #" + treeEnd + ")";
    }
}
function eventSetIndexToPrefix(eventSet) {
    // 64 is one before 'A', so eventSet 1:A, 2:B, etc.
    return eventSet > 0 ? String.fromCharCode(64 + eventSet) : '';
}
function covIssueToSarifResult(ruleId, iss, opts) {
    var sarifLocations = [];
    var remediationEvents = [];
    var mainEventMessage = '';
    var mainLocation = sarifUtils.makeLocation(rewriteUriForGithub(iss.mainEventFilePathname, opts), iss.mainEventLineNumber);
    // Walks all events in the event tree and removes remediation events, adding
    // them to 'remediationEvents'. Also looks for the main event to update the
    // mainEventMessage
    function preprocessEvents(events) {
        var filtered = [];
        for (var _i = 0, events_1 = events; _i < events_1.length; _i++) {
            var e = events_1[_i];
            if (e.main) {
                mainEventMessage = e.eventDescription;
            }
            if (e.remediation) {
                remediationEvents.push(e);
            }
            else {
                if (e.events) {
                    e.events = preprocessEvents(e.events);
                }
                filtered.push(e);
            }
        }
        return filtered;
    }
    // Remove all remediation events from the event tree and add them to the
    // remediationEvents array
    var nonRemediationEvents = preprocessEvents(iss.events);
    // Add remediations to locations before the rest of events are added by 'bfOrderEvents'
    for (var _i = 0, remediationEvents_1 = remediationEvents; _i < remediationEvents_1.length; _i++) {
        var e = remediationEvents_1[_i];
        sarifLocations.push(sarifUtils.makeLocation(rewriteUriForGithub(e.filePathname, opts), e.lineNumber, "Remediation advice: " + e.eventDescription));
    }
    // Traverse the event tree in a breadth-first manner, adding them to sarifLocations
    function bfOrderEvents(events) {
        var toProcess = [];
        // Handle an event with a given name, calculating appropriate step numbers
        // for it's children
        function processEvent(arg) {
            // A 'lookback' step
            if (arg.lookbackStep !== null) {
                sarifLocations.push(sarifUtils.makeLocation(rewriteUriForGithub(arg.event.filePathname, opts), arg.event.lineNumber, "See step " + arg.lookbackStep + " to return to event " + arg.eventName + "."));
                return;
            }
            var event = arg.event, eventName = arg.eventName;
            // This should never happen because remediation events are filtered
            // before being processed
            if (event.remediation) {
                return;
            }
            var nextMessage = 'Event #' + eventName + ': ' + event.eventDescription;
            if (nextMessage.slice(-1) !== '.') {
                nextMessage += '.';
            }
            // Length check shouldn't be necessary, but check just in case there
            // is a 0-length array for some reason
            if (event.events && event.events.length) {
                var eventStartIndex_1 = sarifLocations.length + toProcess.length;
                var eventEndIndex = eventStartIndex_1 + event.events.length;
                nextMessage +=
                    ' ' +
                        formatStepsMessage(eventStartIndex_1 + 1, eventEndIndex, eventName + ".1", eventName + "." + event.events.length);
                toProcess.push.apply(toProcess, event.events.map(function (subEvent, i) {
                    return {
                        eventName: eventName + "." + (i + 1),
                        event: subEvent,
                        lookbackStep: null
                    };
                }));
                // Add the step we're currently on as a 'lookback' event
                // The step we're on is length of sarif locations +1 (because this
                // event hasn't been added to that array yet)
                toProcess.push(__assign(__assign({}, arg), { lookbackStep: sarifLocations.length + 1 }));
            }
            sarifLocations.push(sarifUtils.makeLocation(rewriteUriForGithub(event.filePathname, opts), event.lineNumber, nextMessage));
        }
        // An array indexed by event set with the number of events in that event set
        var eventSetEventCounts = [];
        // Populate eventSetEventCounts
        for (var _i = 0, events_2 = events; _i < events_2.length; _i++) {
            var e = events_2[_i];
            if (e.eventSet === eventSetEventCounts.length) {
                eventSetEventCounts.push(1);
            }
            else {
                eventSetEventCounts[e.eventSet] += 1;
            }
        }
        var numEventSets = eventSetEventCounts.length;
        var nextEventSet = 0;
        var eventNumber = 1;
        var eventSetCaptions = iss.checkerProperties.eventSetCaptions || [];
        function lookupCaption(eventSet) {
            return eventSetCaptions.length > 0
                ? eventSetCaptions.length > eventSet
                    ? eventSetCaptions[eventSet]
                    : eventSetCaptions[eventSetCaptions.length - 1]
                : null;
        }
        // Add captions
        // Step numbering is 1-indexed and starts after event set
        // captions and remediations
        var eventStartIndex = numEventSets + remediationEvents.length;
        for (var i = 0; i < eventSetEventCounts.length; i++) {
            var caption = lookupCaption(i);
            var numEventsThisSet = eventSetEventCounts[i];
            var eventNamePrefix = eventSetIndexToPrefix(i);
            var contextMessage = formatStepsMessage(eventStartIndex + 1, eventStartIndex + numEventsThisSet, eventNamePrefix + "1", "" + eventNamePrefix + numEventsThisSet);
            if (caption) {
                contextMessage =
                    caption + (caption.slice(-1) !== '.' ? '. ' : ' ') + contextMessage;
            }
            sarifLocations.push(__assign(__assign({}, mainLocation), { message: {
                    text: "Event Set " + (i + 1) + ": " + contextMessage
                } }));
            eventStartIndex += numEventsThisSet;
        }
        // Add top level events to the toProcess array with a name derived from
        // its event set
        for (var _a = 0, events_3 = events; _a < events_3.length; _a++) {
            var e = events_3[_a];
            // Are we in a new event set?
            if (e.eventSet === nextEventSet) {
                nextEventSet += 1;
                eventNumber = 1;
            }
            var eventName = eventSetIndexToPrefix(e.eventSet) + eventNumber;
            toProcess.push({ event: e, eventName: eventName, lookbackStep: null });
            eventNumber += 1;
        }
        while (toProcess.length > 0) {
            processEvent(toProcess[0]);
            toProcess = toProcess.slice(1); // tail
        }
    }
    // Process all events
    bfOrderEvents(nonRemediationEvents);
    // Add remediation advice to the main event message if it occurs at the
    // same location as the main event
    var remediationAdvice = remediationEvents
        .filter(function (e) {
        return e.filePathname === iss.mainEventFilePathname &&
            e.lineNumber === iss.mainEventLineNumber;
    })
        .map(function (e) { return e.eventDescription; })
        .join('\n');
    // Form the main result message.
    var resultMessage = iss.checkerName + ": " + mainEventMessage;
    if (remediationAdvice !== '') {
        resultMessage += '\nRemediation Advice: ' + remediationAdvice;
    }
    var result = {
        ruleId: ruleId,
        message: {
            text: resultMessage
        },
        locations: [mainLocation],
        partialFingerprints: {
            primaryLocationLineHash: iss.mergeKey
        },
        codeFlows: [
            {
                threadFlows: [
                    {
                        locations: sarifLocations.map(function (x) {
                            return { location: x };
                        })
                    }
                ]
            }
        ]
    };
    return result;
}
function main(opts) {
    return __awaiter(this, void 0, void 0, function () {
        var toolDriverName, minSupportedJsonVersion, ruleIdSet, rules, resultsOut, firstSarifOutput, covToSarifStream;
        return __generator(this, function (_a) {
            toolDriverName = 'Coverity';
            minSupportedJsonVersion = 7;
            ruleIdSet = new Set() // hash set
            ;
            rules = [];
            fs.writeFileSync(opts.outputFile, sarifUtils.sarifJsonHeader(), {
                encoding: 'utf-8'
            });
            resultsOut = fs.createWriteStream(opts.outputFile, {
                encoding: 'utf-8',
                flags: 'a'
            });
            firstSarifOutput = true;
            covToSarifStream = new stream_1.Transform({
                objectMode: true,
                transform: function (value, encoding, cb) {
                    var ruleId = sarifUtils.formRuleID(value.checkerName, value.type, value.subtype, value['code-language'] ? value['code-language'] : ' ');
                    if (!ruleIdSet.has(ruleId)) {
                        ruleIdSet.add(ruleId);
                        rules.push(sarifUtils.covIssueToRule(ruleId, value));
                    }
                    var sarifResultString = JSON.stringify(covIssueToSarifResult(ruleId, value, opts));
                    if (firstSarifOutput) {
                        firstSarifOutput = false;
                        cb(null, sarifResultString);
                    }
                    else {
                        cb(null, '\n,' + sarifResultString);
                    }
                }
            });
            return [2 /*return*/, new Promise(function (resolve, reject) {
                    var pl = stream_1.pipeline([
                        fs.createReadStream(opts.inputFile, { encoding: 'utf-8' }),
                        JSONStream.parse('issues.*'),
                        covToSarifStream,
                        resultsOut
                    ], function (err) {
                        if (err) {
                            reject(err);
                        }
                        else {
                            fs.writeFileSync(opts.outputFile, sarifUtils.sarifJsonFooter(toolDriverName, rules), {
                                encoding: 'utf-8',
                                flag: 'a'
                            });
                            resolve();
                        }
                    });
                })];
        });
    });
}
function validateRepo(repo) {
    if (repo.match(/^[\w\d-_.]+\/[\w\d-_.]+$/) === null) {
        return "The repository \"" + repo + "\" is not in the format user/repo where \"user\" and \"repo\" contain only alphanumeric characters, dashes, underscores, and periods.";
    }
    return null;
}
function validatePaths(paths) {
    for (var _i = 0, _a = Object.keys(paths); _i < _a.length; _i++) {
        var x = _a[_i];
        var result = validateRepo(x);
        if (result) {
            return result;
        }
    }
    return null;
}
// Update opts with the provided arguments.
// Assumption: args is the appropriate size for key
function populateOpts(opts, key, args) {
    switch (key) {
        case 'checkoutPaths':
            var paths = opts.checkoutPaths ? opts.checkoutPaths : {};
            var repoName = args[0];
            if (repoName in paths) {
                console.log("Error: The repository \"" + repoName + "\" was specified more than once.");
                process.exit(2);
            }
            paths[repoName] = {
                // Strips trailing slashes from the checkout path
                checkoutPath: args[1].replace(/[\\\/]+$/, ''),
                commit: args[2]
            };
            opts.checkoutPaths = paths;
            break;
        case 'inputFile':
        case 'outputFile':
        case 'repoName':
            opts[key] = args[0];
            break;
        case 'githubUrl':
            // Trim all trailing slashes from the provided url
            opts[key] = args[0].replace(/\/+$/, '');
            break;
    }
}
// The first two arguments should always be "node" and the path to this script
var args = process.argv.slice(2);
// processArgs will exit when malformed args are passed
var opts = command_line_1.processArgs(cmdLineSpec, defOpts, args, populateOpts);
// Validates that a --checkoutPath was specified for the repo specified by --repoName
if (Object.keys(opts.checkoutPaths).indexOf(opts.repoName) === -1) {
    sarifUtils.failWithExitCode2('Error: --checkoutPath must be specified for the repository specified by --repoName.');
}
// Check that we're consuming Coverity Desktop JSON v7 or above
// This could be done in a way that doesn't parse the file a second time.
// However, since we're only interested in the "type" and "formatVersion"
// fields, and these fields are almost always going to be near the start
// of the file, very little extra work is done parsing the file as far as
// these fields; usually only a single chunk of the file is read.
// In the case where these fields are at the end of the file, we still have
// to traverse the whole file before doing any "real" work because we can't
// start processing issues until we know we have a supported file.
var formatVersionField = null;
var typeField = null;
var checkCompatibilityPromise = new Promise(function (resolve, reject) {
    var inFileStream = fs.createReadStream(opts.inputFile, {
        encoding: 'utf-8'
    });
    inFileStream.on('error', function () {
        return sarifUtils.failWithExitCode2('Error reading input file. Please make sure the file exists and is readable.');
    });
    inFileStream.on('close', function () {
        resolve();
    });
    function otherFieldsCallback(data) {
        if (typeof data === 'object') {
            if ('formatVersion' in data) {
                formatVersionField = data.formatVersion;
            }
            if ('type' in data) {
                typeField = data.type;
            }
        }
        if (formatVersionField !== null && typeField !== null) {
            inFileStream.destroy();
        }
    }
    var jsonStream = JSONStream.parse('issues.*');
    jsonStream.on('header', otherFieldsCallback);
    jsonStream.on('footer', otherFieldsCallback);
    jsonStream.on('data', function () {
        /* pass */
    });
    jsonStream.on('error', reject);
    inFileStream.pipe(jsonStream);
});
// Check for a compatible input file, then run main
checkCompatibilityPromise.catch(sarifUtils.failWithExitCode4).then(function () {
    if (formatVersionField === null || typeField !== 'Coverity issues') {
        sarifUtils.failWithExitCode2('Invalid Coverity Desktop JSON. One or more required fields are missing: "formatVersion" and "type".');
    }
    if (formatVersionField < 7) {
        sarifUtils.failWithExitCode2('Invalid JSON version: cov-format-sarif-for-github supports Coverity Desktop JSON version 7 and higher.');
    }
    main(opts)
        .then(function () { return process.exit(0); })
        .catch(sarifUtils.failWithExitCode4);
});
