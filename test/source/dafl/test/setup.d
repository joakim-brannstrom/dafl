/**
Copyright: Copyright (c) 2019, Joakim Brännström. All rights reserved.
License: $(LINK2 http://www.boost.org/LICENSE_1_0.txt, Boost Software License 1.0)
Author: Joakim Brännström (joakim.brannstrom@gmx.com)
*/
module dafl.test.setup;

public import logger = std.experimental.logger;
public import std;

public import unit_threaded.assertions;

/// Path to where data used for integration tests exists
string testData() {
    return "testdata".absolutePath;
}

string inTestData(string p) {
    return buildPath(testData, p);
}

private string tmpDir() {
    return "build/test".absolutePath;
}

auto makeTestArea(string file = __FILE__, int line = __LINE__) {
    return TestArea(file, line);
}

struct TestArea {
    const string sandboxPath;
    uint logCnt;

    this(string file, int line) {
        sandboxPath = buildPath(tmpDir, file.baseName ~ line.to!string).absolutePath;

        if (exists(sandboxPath)) {
            rmdirRecurse(sandboxPath);
        }
        mkdirRecurse(sandboxPath);
    }

    auto exec(Args...)(auto ref Args args_) {
        static import std.process;

        string[] args;
        static foreach (a; args_)
            args ~= a;

        auto log = File(inSandboxPath(format("command%s.log", logCnt++)), "w");

        log.writefln("%-(%s %)", args);

        return spawnProcess(args, std.stdio.stdin, log, log, null, Config.none, sandboxPath).wait;
    }

    string inSandboxPath(const string fileName) @safe pure nothrow const {
        import std.path : buildPath;

        return buildPath(sandboxPath, fileName);
    }
}
