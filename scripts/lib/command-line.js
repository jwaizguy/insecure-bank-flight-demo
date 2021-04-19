"use strict";
// Copyright (c) 2021 Synopsys, Inc. All rights reserved worldwide.
Object.defineProperty(exports, "__esModule", { value: true });
exports.processArgs = exports.printUnrecognizedArgumentAndExit = exports.printIncorrectArgsAndExit = exports.verifyCmdLine = exports.printMissingArgumentAndExit = exports.printHelpText = void 0;
var process = require("process");
function printHelpText(cmdLineSpec) {
    var optKeys = Object.keys(cmdLineSpec.options);
    var flags = [];
    var descriptions = [];
    for (var _i = 0, optKeys_1 = optKeys; _i < optKeys_1.length; _i++) {
        var k = optKeys_1[_i];
        var _a = cmdLineSpec.options[k], longSwitch = _a.longSwitch, shortSwitch = _a.shortSwitch, paramHelp = _a.paramHelp, required = _a.required, helpText = _a.helpText;
        var formatedArgString = paramHelp.join(' ');
        if (required) {
            flags.push(longSwitch + ' ' + formatedArgString);
        }
        else {
            flags.push('[' + longSwitch + ' ' + formatedArgString + ']');
        }
        descriptions.push("" + longSwitch + (shortSwitch ? ', ' + shortSwitch : '') + "\n\t" + helpText);
    }
    console.log(cmdLineSpec.program, ':', cmdLineSpec.summary);
    console.log('Usage:');
    console.log('node', cmdLineSpec.program, flags.join(' '), '\n');
    console.log('Flags:');
    console.log(descriptions.join('\n'), '\n');
    console.log('Example:');
    console.log(cmdLineSpec.examples);
}
exports.printHelpText = printHelpText;
// Print a message for the missing command line parameter 'opt'
function printMissingArgumentAndExit(opt) {
    console.log("Error: The required command line argument " + opt.longSwitch + " was not provided.");
    process.exit(2);
}
exports.printMissingArgumentAndExit = printMissingArgumentAndExit;
// Validate toValidate against optionsSpec
function verifyCmdLine(optionsSpec, toValidate) {
    var optKeys = Object.keys(optionsSpec);
    // Verify required argument existance
    for (var _i = 0, optKeys_2 = optKeys; _i < optKeys_2.length; _i++) {
        var k = optKeys_2[_i];
        var opt = toValidate[k];
        if (typeof opt === 'undefined') {
            printMissingArgumentAndExit(optionsSpec[k]);
        }
        for (var _a = 0, _b = optionsSpec[k].validators; _a < _b.length; _a++) {
            var validator = _b[_a];
            var validationResult = validator(opt);
            if (validationResult) {
                console.log("Error: Validation of the option --" + k + " failed with the message:");
                console.log(validationResult);
                process.exit(2);
            }
        }
    }
    // @ts-ignore
    // We've validated that all keys are present using optKeys, which is guaranteed
    // to have the keys of CovFormatSarifForGithubOptions. Getting Typescript to narrow
    // the type of toValidate so it recognizes this is true is more hassle than its worth,
    // hence using ts-ignore.
    var validated = toValidate;
    return validated;
}
exports.verifyCmdLine = verifyCmdLine;
function printIncorrectArgsAndExit(arg, numGiven) {
    console.log('Error: The argument ' +
        arg.longSwitch +
        ' expects ' +
        arg.numParams +
        ' parameters but ' +
        numGiven +
        ' were provided.');
    process.exit(2);
}
exports.printIncorrectArgsAndExit = printIncorrectArgsAndExit;
function printUnrecognizedArgumentAndExit(arg) {
    console.log("Error: Encountered the unrecognized command line switch \"" + arg + "\".");
    process.exit(2);
}
exports.printUnrecognizedArgumentAndExit = printUnrecognizedArgumentAndExit;
function processArgs(cmdLineSpec, defOpts, args, updateOpts) {
    var opts = defOpts;
    // As a special case, print the help text if no arguments are specified
    if (args.length === 0) {
        printHelpText(cmdLineSpec);
        process.exit(0);
    }
    // Returns either the CommandLineSpec key corresponding to the switch, or
    // null if the argument is not a switch
    function getOptionKeyFromSwitch(arg) {
        for (var _i = 0, _a = Object.keys(cmdLineSpec.options); _i < _a.length; _i++) {
            var k = _a[_i];
            var _b = cmdLineSpec.options[k], longSwitch = _b.longSwitch, shortSwitch = _b.shortSwitch;
            if (arg === longSwitch || arg === shortSwitch) {
                return k;
            }
        }
        return null;
    }
    // A list of command line switches and the arguments that follow that are not switches
    var parsedOpts = [];
    var firstParam = args.shift();
    var firstArg = getOptionKeyFromSwitch(firstParam);
    if (firstArg === null) {
        printUnrecognizedArgumentAndExit(firstParam);
    }
    parsedOpts.push([firstArg, []]);
    while (args.length > 0) {
        // args is a string[] and args.length > 0 so arg must be a string. Typescript
        // thinks it's string|undefined because of the return type of shift.
        var arg = args.shift();
        var key = getOptionKeyFromSwitch(arg);
        if (key !== null) {
            parsedOpts.push([key, []]);
        }
        else {
            parsedOpts[parsedOpts.length - 1][1].push(arg);
        }
    }
    for (var _i = 0, parsedOpts_1 = parsedOpts; _i < parsedOpts_1.length; _i++) {
        var _a = parsedOpts_1[_i], k = _a[0], vs = _a[1];
        if (k === 'help') {
            printHelpText(cmdLineSpec);
            process.exit(0);
        }
        var opt = cmdLineSpec.options[k];
        if (opt.numParams !== vs.length) {
            printIncorrectArgsAndExit(opt, vs.length);
        }
        updateOpts(opts, k, vs);
    }
    return verifyCmdLine(cmdLineSpec.options, opts);
}
exports.processArgs = processArgs;
