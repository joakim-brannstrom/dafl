/**
Copyright: Copyright (c) 2019, Joakim Brännström. All rights reserved.
License: $(LINK2 http://www.boost.org/LICENSE_1_0.txt, Boost Software License 1.0)
Author: Joakim Brännström (joakim.brannstrom@gmx.com)
*/
import std.exception, std.file, std.path, std.process, std.stdio;

int main(string[] args) {
    writeln("===============================");
    writeln("Redirecting testing to: ", buildPath(getcwd, "test"));

    // make sure the build is pristine
    if (spawnProcess(["dub", "build", "-c", "application"]).wait != 0) {
        return -1;
    }

    chdir("test");

    args = () {
        if (args.length > 1)
            return args[1 .. $];
        return null;
    }();

    rmdirRecurse("build/test").collectException;
    mkdirRecurse("build/test").collectException;

    return spawnProcess(["dub", "test", "--"] ~ args).wait;
}
