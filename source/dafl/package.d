/**
Copyright: Copyright (c) 2019, Joakim Brännström. All rights reserved.
License: $(LINK2 http://www.boost.org/LICENSE_1_0.txt, Boost Software License 1.0)
Author: Joakim Brännström (joakim.brannstrom@gmx.com)

See [how to write an afl wrapper](https://robertheaton.com/2019/07/08/how-to-write-an-afl-wrapper-for-any-language/).


This function will need to mimic the functionality of afl’s __AFL_INIT:

 * Initialize the shared memory segment that our program will share with afl
 * Loop forever, forking off child processes that run test cases by executing the rest of the fuzz harness
 * Report the exit statuses of these child processes to the forkserver

```
def afl_init()
  # Initialize the memory segment that our
  # program shares with afl
  init_shm()

  # Initialize and ensure that we can
  # communicate with afl's forkserver.
  init_forkserver()

  # Loop the parent process forever,
  # forking off child processes and
  # reporting their outcomes to afl.
  while True do
    # Drain the forkserver's output in
    # order to indicate to afl that we
    # are about to run another test case.
    forkserver_read()

    # Fork a child process. In the new
    # child process, child_pid will be
    # set to nil. In the parent, it will
    # be set to the pid of the child.
    child_pid = fork

    # If child_pid is nil then we are
    # the child process, so we return
    # from `afl_init` and run a test
    # case by executing the rest of the
    # harness.
    break if child_pid == nil

    # If child_pid is not nil then we
    # are the parent, so our job is to
    # monitor and report the status of
    # the child.
    #
    # First we write child_pid to the
    # afl forkserver.
    forkserver_write(child_pid)

    # Then we wait for the child process
    # to finish and record its status.
    status = waitpid2(child_pid)

    # Finally we report this status to
    # afl so that it knows if the test
    # case resulted in a crash or not.
    forkserver_write(status)

    # Now that the child process has
    # finished, we (the parent) go back
    # to the top of the loop in order
    # to fork another child and run
    # another test case.
  end

  # Close the forksrv file descriptors.
  # This line will only ever be reached
  # by the child process.
  close_forksrv_fds()
end
```
*/
module dafl;

import std;
import logger = std.experimental.logger;

version (unittest) {
    import unit_threaded.assertions;
}

auto defaultProcessFuzzer(string[] cmd) {
    auto conf = Config!(AflBasicConstants, SpawnProcess)(SpawnProcess(cmd));
    return makeAfl(conf);
}

/** Thrown when an error occurs that is unrecoverable.
 */
class AflException : Exception {
    this(string msg, string file = __FILE__, int line = __LINE__) @safe pure nothrow {
        super(msg, file, line);
    }
}

/** Derived from afl-fuzz.
 *
 * These need to be in sync with your afl-fuzz installation.
 */
struct AflBasicConstants {
    static immutable envKey = "__AFL_SHM_ID";
    static immutable forkSrvFd = 198;
    static immutable mapSizePow2 = 16;
    static immutable mapSize = 1 << mapSizePow2;
}

/** Configuration of dafl for how to spawn the a new test and understand its
 * output.
 *
 * Params:
 * SpawnT = ?
 */
struct Config(ConstantsT, SpawnT) {
    alias Constants = ConstantsT;
    SpawnT spawn;
}

/**
 * We need to be able to inform afl:
 * * When a new test case is about to run.
 * * When a test case has finished running.
 * * Whether a completed test case resulted in a crash or not.
 *
 * In afl’s deferred forkserver mode, our main process doesn’t run test cases.
 * Instead, our main process’s job is to spawn and manage child processes, and
 * it is these that actually run test cases. Our main, parent process should
 * run in an infinite loop, and with each pass it should fork off a new child
 * process, wait for the child to run a test case, and report the child’s exit
 * status to afl.
 */
struct Afl(ConfigT) {
    ConfigT conf;
    AflShm shm;
    ForkServer server;
    bool running;

    void run() {
        running = true;
        while (running) {
            runOnce;
        }
    }

    void runOnce() {
        // Read and discard the previous test's status. We don't care about
        // the value, but if we don't read it, the fork server eventually
        // blocks, and then we block on the call to _forkserver_write
        // below.
        server.discarServerPing;
        auto child = conf.spawn();

        // TODO: add a static if to check if it is a "fork" or separate process

        server.write(child.pid);

        const int status = child.wait;
        foreach (const t; child.trace()) {
            shm.update(t);
        }

        server.write(status);
    }
}

auto makeAfl(ConfigT)(ConfigT conf) {
    alias Constants = ConfigT.Constants;

    return Afl!ConfigT(conf, initAflShm(Constants.envKey), forkServer(Constants.forkSrvFd));
}

@safe:

/// The shm used to communicate with AFL.
struct AflShm {
    /// Shared memory area ID.
    uint id;
    /// Memory area to write to.
    ubyte[] area;

    /** Update the counter in the shared memory by one at addr.
     */
    void update(uint addr) @safe nothrow @nogc {
        area[addr % area.length] += 1;
    }
}

/**
 * We’ll start by attaching our program to afl’s shared memory segment. This is
 * where afl expects us to write information about our program’s execution
 * path.
 *
 * First, we will get the segment’s address in memory. Afl writes this address
 * to the __AFL_SHM_ID environment variable, which we should be able to read
 * without any trouble. Next, once we have the segment’s address, we can use
 * the shmat syscall to attach it to our program’s memory space. Finally, we
 * will store the address returned by shmat in a variable so that we can use it
 * later to write execution path data to the shared memory segment.
 */
auto initAflShm(string envKey) @trusted {
    const id = () {
        auto v = environment.get(envKey, null);
        if (v is null)
            throw new AflException(
                    "Unable to find the AFL shared memory. No value set for environment variable "
                    ~ envKey);
        return v.to!uint;
    }();

    import core.sys.posix.sys.shm : shmat, shmctl, shmid_ds;
    import core.sys.posix.sys.ipc : IPC_STAT;

    ubyte* areaPtr = cast(ubyte*) shmat(id, null, 0);

    if (areaPtr == cast(void*)-1)
        throw new AflException(
                "Unable to attach to AFLs shared memory region. ID obtained from the environment variable "
                ~ envKey);

    // Write something into the bitmap so that even with low AFL_INST_RATIO,
    // our parent doesn't give up on us.
    *areaPtr = 1;

    shmid_ds ds;
    if (shmctl(id, IPC_STAT, &ds) == -1) {
        throw new AflException(
                "Unable to retrieve stats for th AFL shared memory region obtained from the environment variable "
                ~ envKey);
    }

    return AflShm(id, cast(ubyte[]) areaPtr[0 .. ds.shm_segsz]);
}

struct ForkServer {
    static import std.io;

    RefCounted!(std.io.file.File, RefCountedAutoInitialize.no) readPipe;
    RefCounted!(std.io.file.File, RefCountedAutoInitialize.no) writePipe;

    size_t write(const scope ubyte[] buffer) @safe @nogc {
        return writePipe.write(buffer);
    }

    void write(int v) @trusted @nogc {
        ubyte[int.sizeof] buf = void;
        buf[] = (cast(ubyte*)&v)[0 .. int.sizeof];
        this.write(buf);
    }

    size_t read(scope ubyte[] buffer) @safe @nogc {
        return readPipe.read(buffer);
    }

    void discarServerPing() @safe @nogc {
        ubyte[4] buf = void;
        this.read(buf[]);
        // TODO: maybe warn if the read data isn't 4?
    }
}

ForkServer forkServer(int forkSrvFd) @trusted {
    import std.io;

    auto rval = ForkServer(refCounted(std.io.file.File(forkSrvFd)),
            refCounted(std.io.file.File(forkSrvFd + 1)));

    // make reading from the pipe nonblocking as to not get stuck on waiting

    // At the start of its afl_init method, afl checks that the
    // forkserver-write pipe is working by writing 4 null bytes to the pipe and
    // bailing if anything goes wrong.
    ubyte[4] ping;
    if (rval.write(ping[]) != 4) {
        throw new AflException("Unable to open communication over pipe " ~ (forkSrvFd + 1)
                .to!string ~ " with AFL");
    }

    return rval;
}

/**
 * Returns the location in the AFL shared memory to write the given trace data
 * to.
 *
 * Borrowed from afl-python for consistency
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 *
 * TODO: replace the hash with one from phobos.
 *
 * Params:
 * data = data to hash.
 */
uint basicHash(const(ubyte)[] data) @safe pure nothrow @nogc {
    size_t len = data.length;
    uint h = 0x811C9DC5;
    while (len > 0) {
        h ^= cast(uint) data[0];
        h *= 0x01000193;
        len -= 1;
        data = data[1 .. $];
    }
    return h;
}

/**
 * Returns the location in the AFL shared memory to write the given trace data
 * to.
 *
 * Borrowed from afl-python for consistency
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 *
 * TODO: replace the hash with one from phobos.
 *
 * Params:
 * h = hash to start with.
 * offset = hash the offset onto `h` e.g. such as a line number if data is the filename.
 */
uint basicHash(uint h, size_t offset) @safe pure nothrow @nogc {
    while (offset > 0) {
        h ^= cast(uint) offset;
        h *= 0x01000193;
        offset >>= uint.sizeof;
    }
    return h;
}

struct PathNode {
    const(ubyte)[] data;
    uint offset;
}

/**
 *
 */
struct AflHashPath(alias hashFn, alias hashOffsetFn, ConstantsT) {
    uint prev;

    uint next(scope PathNode node) @safe pure nothrow @nogc {
        return next(hashFn(node.data), node.offset);
    }

    uint next(const uint h, const uint offset) @safe pure nothrow @nogc {
        const uint curr = (hashOffsetFn(h, offset) % ConstantsT.mapSize) ^ prev;
        prev = curr;
        return curr;
    }

    void reset() @safe pure nothrow @nogc {
        prev = 0;
    }
}

/** Use for testing a binary to observer how its output data is changed
 * depending on the input.
 */
struct SpawnProcess {
    static import std.process;

    string[] cmd;

    this(string[] cmd) {
        this.cmd = cmd;
    }

    Process opCall() @safe const {
        return Process(pipeProcess(cmd, std.process.Redirect.stdout | std.process.Redirect.stderrToStdout,
                null, std.process.Config.retainStdin));
    }

    static struct Process {
        ProcessPipes proc;
        Appender!(ubyte[]) data;

        auto pid() {
            return proc.pid.osHandle;
        }

        uint wait() {
            import core.thread : Thread;
            import core.time : dur;

            ubyte[1024] buf;

            while (true) {
                auto res = tryWait(proc.pid);
                auto readData = proc.stdout.rawRead(buf[]);
                data.put(readData);
                if (res.terminated) {
                    return res.status;
                }

                // TODO: maybe this sleep isn't necessary if rawRead blocks if there are no data.
                // TODO: this could be made on the fly too. I mean, instead of
                // buffering we could directly write to the shm.
                if (readData.length < buf.length) {
                    () @trusted { Thread.sleep(10.dur!"msecs"); }();
                }
            }
        }

        TraceRange trace() @safe pure nothrow const @nogc {
            return TraceRange(data.data);
        }
    }

    static struct TraceRange {
    pure @nogc nothrow:
        enum Sz = 8;

        const(ubyte)[] data;
        AflHashPath!(basicHash, basicHash, AflBasicConstants) path;
        uint counter = 1;
        uint curr;

        this(const(ubyte)[] data) {
            this.data = data;

            if (!data.empty)
                popFront;
        }

        uint front() @safe pure nothrow {
            assert(!empty, "Can't get front of an empty range");
            return curr;
        }

        void popFront() @safe pure nothrow {
            assert(!empty, "Can't pop front of an empty range");

            counter++;

            if (data.length == 0) {
                counter = 0;
            } else if (data.length < Sz) {
                curr = path.next(PathNode(data[0 .. $], counter));
                data = null;
            } else {
                curr = path.next(PathNode(data[0 .. 8], counter));
                data = data[Sz .. $];
            }
        }

        bool empty() @safe pure nothrow const @nogc {
            return counter == 0;
        }
    }
}

version (unittest) {
    struct AflTestEnv {
        import core.sys.posix.sys.shm : shmget, shmctl, IPC_CREAT, IPC_PRIVATE, IPC_RMID, shmat;
        import core.sys.posix.sys.stat : S_IRUSR, S_IWUSR;
        import core.sys.posix.unistd : pipe, dup2, close, read, write;

        enum ClientStart {
            value,
        }

        enum ClientStop {
            value,
        }

        enum ClientNext {
            value,
        }

        int[2] pipeFdTo, pipeFdFrom;
        int shmId;
        ubyte[] area;
        int pipeTo;
        int pipeFrom;
        Tid client;

        this(int shmId, ubyte[] area, int[2] to, int[2] from) {
            this.shmId = shmId;
            this.area = area;

            this.pipeFdTo = to;
            this.pipeFdFrom = from;

            this.pipeTo = to[1];
            this.pipeFrom = from[0];
        }

        ~this() @trusted {
            shmctl(shmId, IPC_RMID, null);
            foreach (const fd; pipeFdTo[])
                close(fd);
            foreach (const fd; pipeFdFrom[])
                close(fd);
        }

        void startClient(immutable string[] cmd) @trusted {
            static void actor(immutable string[] cmd) {
                receiveOnly!ClientStart;
                auto inst = defaultProcessFuzzer(cmd.dup);

                bool running = true;
                while (running) {
                    receive((ClientStop a) { running = false; }, (ClientNext a) {
                        inst.runOnce;
                    });
                }
                send(ownerTid, true);
            }

            client = spawn(&actor, cmd);
        }

        void nextClient() @trusted {
            send(client, ClientNext.value);
        }

        void stopClient() @trusted {
            send(client, ClientStop.value);
            receiveOnly!bool;
        }

        void interactInitPing() @trusted {
            send(client, ClientStart.value);

            ubyte[8] buf = void;
            read(pipeFrom, &buf, buf.length).shouldEqual(4);
            logger.trace("Reading client ping: ", buf[0 .. 4]);
        }

        static struct Response {
            int pid;
            int status;
        }

        Response interact() @trusted {
            immutable Sz = 4;
            Response rval;

            ubyte[8] buf = void;
            logger.trace("Sending server ping");
            buf[0] = 42;
            write(pipeTo, &buf, Sz);

            read(pipeFrom, &buf, buf.length).shouldEqual(Sz);
            (cast(ubyte*)&rval.pid)[0 .. Sz] = buf[0 .. Sz];
            logger.tracef("Reading client pid: %s %s", rval.pid, buf[0 .. Sz]);

            read(pipeFrom, &buf, buf.length).shouldEqual(Sz);
            (cast(ubyte*)&rval.status)[0 .. Sz] = buf[0 .. Sz];
            logger.tracef("Reading client status: %s %s", rval.status, buf[0 .. Sz]);

            return rval;
        }

        static auto make() @trusted {
            const fakeAflId = shmget(IPC_PRIVATE, AflBasicConstants.mapSize,
                    IPC_CREAT | S_IRUSR | S_IWUSR);
            ubyte[] area = (cast(ubyte*) shmat(fakeAflId, null, 0))[0 .. AflBasicConstants.mapSize];
            environment[AflBasicConstants.envKey] = fakeAflId.to!string;

            int[2] pipeTo, pipeFrom;
            pipe(pipeTo).shouldEqual(0);
            pipe(pipeFrom).shouldEqual(0);

            dup2(pipeTo[0], AflBasicConstants.forkSrvFd);
            dup2(pipeFrom[1], AflBasicConstants.forkSrvFd + 1);

            return AflTestEnv(fakeAflId, area, pipeTo, pipeFrom);
        }
    }
}

// use this to cleanup stale system v shared memory objects
// ipcs|grep 65536|awk '{print $2}'| xargs -n1 ipcrm -m

@("shall instantiate the default AFL integration")
@system unittest {
    auto env = AflTestEnv.make();
    auto inst = defaultProcessFuzzer(["echo"]);
}

@("shall communicate the result via the afl shm/pipe protocol when running echo in the Afl wrapper")
@system unittest {
    auto env = AflTestEnv.make();
    env.startClient(["echo"]);
    env.interactInitPing;
    env.nextClient;
    env.interact;
    env.stopClient;
}

@("shall update the shared memory with the output from echo hello world")
unittest {
    auto env = AflTestEnv.make();

    env.area.sum.shouldEqual(0);

    env.startClient(["echo", "hello", "world"]);
    env.interactInitPing;
    env.nextClient;
    env.interact;
    env.stopClient;

    // the stream from echo is 10 bytes which mean that the initial and the 10
    // bytes result in three updates.
    env.area.sum.shouldEqual(3);
}
