"use strict";
// Copyright (c) 2021 Synopsys, Inc. All rights reserved worldwide.
Object.defineProperty(exports, "__esModule", { value: true });
exports.covIssueToRule = exports.formLevel = exports.formRuleID = exports.makeLocation = exports.makeSARIFLog = exports.sarifJsonFooter = exports.sarifJsonHeader = exports.failWithExitCode4 = exports.failWithExitCode2 = void 0;
function failWithExitCode2(msg) {
    console.log(msg);
    process.exit(2);
}
exports.failWithExitCode2 = failWithExitCode2;
function failWithExitCode4(e) {
    if (e.stack) {
        console.log(e.stack);
    }
    else {
        console.log(e.toString());
    }
    process.exit(4);
}
exports.failWithExitCode4 = failWithExitCode4;
function sarifJsonHeader() {
    return "{\n  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\",\n  \"version\": \"2.1.0\",\n  \"runs\": [{\n    \"results\":\n[";
}
exports.sarifJsonHeader = sarifJsonHeader;
function sarifJsonFooter(toolDriverName, rules) {
    return "\n],\n    \"tool\": {\n      \"driver\": {\n        \"name\": \"" + toolDriverName + "\",\n        \"organization\": \"Synopsys\",\n        \"rules\": " + JSON.stringify(rules) + "\n      }\n    }\n  }]\n}";
}
exports.sarifJsonFooter = sarifJsonFooter;
function makeSARIFLog(toolDriverName, rules, results) {
    var sarifLog = {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
            {
                tool: {
                    driver: {
                        name: toolDriverName,
                        organization: 'Synopsys',
                        rules: rules
                    }
                },
                results: results
            }
        ]
    };
    return sarifLog;
}
exports.makeSARIFLog = makeSARIFLog;
function makeLocation(filename, startLine, message) {
    var loc = {
        physicalLocation: {
            artifactLocation: {
                uri: filename
            },
            region: {
                startLine: startLine
            }
        }
    };
    if (message) {
        loc.message = {
            text: message
        };
    }
    return loc;
}
exports.makeLocation = makeLocation;
function formRuleID(checkerName, type, subtype, codeLang) {
    // NOTE: In issueTypes.json,
    // Valid type/subtype strings must be 1-64 characters in {a-zA-Z0-9_.}
    // Use "_" if any of the component keys are missing
    if (!type)
        type = '_';
    if (!subtype)
        subtype = '_';
    if (!codeLang)
        codeLang = '_';
    return (checkerName +
        '/' +
        type +
        '/' +
        subtype +
        '/' +
        codeLang.replace(/\//g, '_'));
}
exports.formRuleID = formRuleID;
function formLevel(impact) {
    // see SARIF spec: 3.27.10 level property
    // "warning": The rule specified by ruleId was evaluated and a problem was found.
    // "error": The rule specified by ruleId was evaluated and a serious problem was found.
    // "note": The rule specified by ruleId was evaluated and a minor problem or an opportunity to improve the code was found.
    // "none": The concept of “severity” does not apply to this result because the kind property (§3.27.9) has a value other than "fail".
    switch (impact) {
        case 'Audit':
            return 'warning';
        case 'High':
            return 'error';
        case 'Low':
            return 'note';
        case 'Medium':
            return 'warning';
        default:
            console.log('Unexpected impact string in Coverity JSON ("' + impact + '")');
            return 'warning';
    }
}
exports.formLevel = formLevel;
// "Rule" is actually a "ReportingDescriptor" in SARIF spec
function covIssueToRule(ruleId, iss) {
    var strippedLongDesc = iss.checkerProperties.subcategoryLongDescription.replace(/\.+$/, '');
    var r = {
        id: ruleId,
        shortDescription: {
            text: iss.checkerProperties.subcategoryShortDescription
        },
        fullDescription: {
            text: strippedLongDesc + ': ' + iss.checkerProperties.subcategoryLocalEffect
        },
        defaultConfiguration: {
            level: formLevel(iss.checkerProperties.impact)
        }
    };
    r.properties = {
        tags: []
    };
    return r;
}
exports.covIssueToRule = covIssueToRule;
