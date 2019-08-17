/**
Copyright: Copyright (c) 2019, Joakim Brännström. All rights reserved.
License: $(LINK2 http://www.boost.org/LICENSE_1_0.txt, Boost Software License 1.0)
Author: Joakim Brännström (joakim.brannstrom@gmx.com)
*/
module app;

import std;
import logger = std.experimental.logger;

import colorlog;

int main(string[] args) {
    confLogger(VerboseMode.info);

    auto conf = parseUserArgs(args);

    if (conf.global.help) {
        return cli(conf);
    }

    if (!conf.global.logFile.empty) {
        logger.globalLogLevel = logger.LogLevel.all;
        logger.sharedLog = new logger.FileLogger(conf.global.logFile);
    } else {
        confLogger(conf.global.verbosity);
    }

    import std.variant : visit;

    // dfmt off
    return conf.data.visit!(
          (Config.Help a) => cli(conf),
          (Config.Exec a) => cli(a, conf.global.logFile),
    );
    // dfmt on
}

private:

int cli(Config conf) {
    conf.printHelp;
    return 0;
}

int cli(Config.Exec conf, string logfile) {
    import dafl;

    static class FuzzLogger : DefaultCallback {
        string logfile;

        this(string logfile) {
            this.logfile = logfile;
        }

        override void end() {
            logger.trace("Done");
            if (!logfile.empty) {
                File(logfile, "w").write();
            }
        }
    }

    logger.info("Waiting for afl forkserver to request data");
    auto afl = defaultProcessFuzzer(conf.cmd, new FuzzLogger(logfile));
    afl.run;

    return 0;
}

struct Config {
    import std.variant : Algebraic;
    static import std.getopt;

    struct Help {
        std.getopt.GetoptResult helpInfo;
    }

    struct Exec {
        bool stdinAsArgument;
        std.getopt.GetoptResult helpInfo;
        string[] cmd;
    }

    struct Global {
        VerboseMode verbosity;
        bool help = true;
        string progName;
        string logFile;
    }

    alias Type = Algebraic!(Help, Exec);
    Type data;

    Global global;

    void printHelp() {
        import std.format : format;
        import std.getopt : defaultGetoptPrinter;
        import std.string : toLower;

        static void printGroup(std.getopt.GetoptResult helpInfo, string progName, string name) {
            defaultGetoptPrinter(format("usage: %s %s <options>\n", progName,
                    name), helpInfo.options);
        }

        static void printHelpGroup(std.getopt.GetoptResult helpInfo, string progName) {
            defaultGetoptPrinter(format("usage: %s <command>\n", progName), helpInfo.options);
            writeln("Command groups:");
            static foreach (T; Type.AllowedTypes) {
                writeln("  ", T.stringof.toLower);
            }
        }

        import std.meta : AliasSeq;

        template printers(T...) {
            static if (T.length == 1) {
                static if (is(T[0] == Config.Help))
                    alias printers = (T[0] a) => printHelpGroup(a.helpInfo, global.progName);
                else
                    alias printers = (T[0] a) => printGroup(a.helpInfo,
                            global.progName, T[0].stringof.toLower);
            } else {
                alias printers = AliasSeq!(printers!(T[0]), printers!(T[1 .. $]));
            }
        }

        data.visit!(printers!(Type.AllowedTypes));
    }
}

Config parseUserArgs(string[] args) {
    import std.format : format;
    import std.string : toLower;
    static import std.getopt;

    Config conf;
    conf.data = Config.Help.init;
    conf.global.progName = args[0].baseName;

    string group;
    if (args.length > 1) {
        group = args[1];
        args = args.remove(1);
    }

    try {
        void globalParse() {
            Config.Help data;
            scope (success)
                conf.data = data;
            // dfmt off
            data.helpInfo = std.getopt.getopt(args, std.getopt.config.passThrough,
                "v|verbose", format("Set the verbosity (%-(%s, %))", [EnumMembers!(VerboseMode)]), &conf.global.verbosity,
                "logfile", "Save the log to this file", &conf.global.logFile,
                );
            // dfmt on
            conf.global.help = data.helpInfo.helpWanted;
            args ~= (conf.global.help ? "-h" : null);
        }

        void execParse() {
            Config.Exec data;
            scope (success)
                conf.data = data;

            // dfmt off
            data.helpInfo = std.getopt.getopt(args,
                "c", "Part of the command to execute. Use multiple to build it", &data.cmd,
                "stdin-as-arg", "Stdin is converted to an argument to the program", &data.stdinAsArgument,
                );
            // dfmt on
        }

        alias ParseFn = void delegate();
        ParseFn[string] parsers;

        static foreach (T; Config.Type.AllowedTypes) {
            static if (!is(T == Config.Help))
                mixin(format(`parsers["%1$s"] = &%1$sParse;`, T.stringof.toLower));
        }

        globalParse;

        if (auto p = group in parsers) {
            (*p)();
        }
    } catch (std.getopt.GetOptException e) {
        // unknown option
        conf.global.help = true;
        logger.error(e.msg);
    } catch (Exception e) {
        conf.global.help = true;
        logger.error(e.msg);
    }

    return conf;
}
