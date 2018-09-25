# Adding a new test

Adding a new test can be fairly involved, but hopefully not impossible. The
existing tests are probably the best reference, especially the ``skeleton``
(client only) and ``remoteskeleton`` (server and client) tests.

Here is a brief overview of the steps required to add a new test:


## 1. Create the source directory for the test

All the tests should be subdirectories of ``src/tests/``, so create a new
directory in there for your test. This is where you will add your source code.
You should also create a subdirectory of your test directory called ``tests``
to store any unit tests you might have.



## 2. Describe the data that will be reported

Result data is serialised using [protocol buffers](https://developers.google.com/protocol-buffers/) and is expected to be formatted a certain way.
Each message sent by the test will contain one ``Report``, which will contain
one ``Header`` and one or more ``Item``, depending on how many destinations
were tested. The ``Header`` should describe all of the fixed configuration
options that were applied to the test run (e.g. packet size, query string, etc).
Each ``Item`` contains the observed/measured results for one single destination
(e.g. latency, throughput, response size, response type, etc).

Most tests capable of testing to multiple destinations will include the
address, address family and name of the destination in the ``Item`` message.
If a test only works to a single destination then you might include this in
the ``Header`` instead.

In your test directory you should create a protocol buffer definition file
that describes your test results. As an example for a test called ``foo``,
you might have a protocol buffer file called ``foo.proto`` that looks something
like this:


    package amplet2.foo;

    /**
     * An instance of the test will generate one Report message.
     */
    message Report {
        /** Describes the test settings used in this test instance */
        optional Header header = 1;
        /** Results for all test targets */
        repeated Item reports = 2;
    }

    /**
     * The test header describes all of the settings that the test was
     * configured to run with. These settings are the same for every result
     * contained within the Report message.
     */
    message Header {
        /** Size of the probe packet in bytes */
        optional uint32 packet_size = 1 [default = 84];
    }

    /**
     * A report will be generated for each test target, describing the target
     * and how long it took to receive the response. All fields are optional -
     * only those with useful and relevant data are included.
     */
    message Item {
        /** The address that responded to the probe packet */
        optional bytes address = 1;
        /** The family the responding address belongs to (AF_INET/AF_INET6) */
        optional int32 family = 2;
        /** The round trip time to the target, measured in microseconds */
        optional uint32 rtt = 3;
    }



## 3. Write your test

Each test is implemented as a shared library that is loaded by
``amplet2-client`` or the standalone test binary when executed. To help load
tests and describe their capabilities they need to export a registration
function called ``register_test`` that is called when the library is loaded.
This will configure the functions used to run the test and print test results,
as well as things such as number of destinations the test can handle. The test
name is used as a label in the schedule files to determine which test to run,
and the test ID is used when communicating between instances of
``amplet2-client`` (e.g. to start a test server) - these should be unique, but
this is not currently enforced.

An example test called ``foo`` that requires at least 1 target (with no
maximum), runs for less than two minutes and doesn't require a cooperating
server might have a registration function that looks something like this:

    test_t *register_test() {
        test_t *new_test = (test_t *)malloc(sizeof(test_t));

        /* unique test identifier */
        new_test->id = 0x12345678;

        /* name is used to schedule the test and report results */
        new_test->name = strdup("foo");

        /* how many targets a single instance of this test can have */
        new_test->max_targets = 0;

        /* minimum number of targets required to run this test */
        new_test->min_targets = 1;

        /* maximum duration this test should take before being killed */
        new_test->max_duration = 120;

        /* function to call to setup arguments and run the test */
        new_test->run_callback = run_foo;

        /* function to call to pretty print the results of the test */
        new_test->print_callback = print_foo;

        /* the foo test doesn't require us to run a custom server */
        new_test->server_callback = NULL;

        /* don't give the foo test a SIGINT warning, it should not take long! */
        new_test->sigint = 0;

        return new_test;
    }

Each test also has some useful functions available to it to help work with
sockets, timing, sending/receiving packets etc provided by ``libamp``.

TODO: document libamp

After your test completes it needs to return an amp_test_result_t, which
includes a timestamp and a protocol buffer message containing all the results.
The calling function will then either send that message across the network or
pass it to the printing function, depending on how it was invoked.

    typedef struct amp_test_result {
        uint64_t timestamp;
        size_t len;
        void *data;
    } amp_test_result_t;

Build up the protocol buffer message containing the ``Report``, the ``Header``
and an ``Item`` for each test result, then pack it into an
``amp_test_result_t``, something like this:

    static amp_test_result_t* report_results(struct timeval *start_time,
            int count, struct info_t info[], struct opt_t *opt) {
        int i;
        amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

        Amplet2__Foo__Report msg = AMPLET2__ICMP__REPORT__INIT;
        Amplet2__Foo__Header header = AMPLET2__ICMP__HEADER__INIT;
        Amplet2__Foo__Item **reports;

        /* populate the header with all the test options */
        header.has_packet_size = 1;
        header.packet_size = opt->packet_size;

        /* build up the repeated reports section with each of the results */
        reports = malloc(sizeof(Amplet2__Foo__Item*) * count);
        for ( i = 0; i < count; i++ ) {
            reports[i] = report_destination(&info[i]);
        }

        /* populate the top level report object with the header and reports */
        msg.header = &header;
        msg.reports = reports;
        msg.n_reports = count;

        /* pack all the results into a buffer for transmitting */
        result->timestamp = (uint64_t)start_time->tv_sec;
        result->len = amplet2__foo__report__get_packed_size(&msg);
        result->data = malloc(result->len);
        amplet2__foo__report__pack(&msg, result->data);

        return result;
    }

If the test is being run standalone then it will call the print callback
function to print the results. This should be able to unpack the
``amp_test_result_t`` and print some useful information to the terminal.

    void print_foo(amp_test_result_t *result) {
        Amplet2__Foo__Report *msg;
        Amplet2__Foo__Item *item;
        unsigned int i;
        char addrstr[INET6_ADDRSTRLEN];

        assert(result);
        assert(result->data);

        /* unpack all the data */
        msg = amplet2__foo__report__unpack(NULL, result->len, result->data);

        assert(msg);
        assert(msg->header);

        /* print test header information */
        printf("\nAMP foo test, %zu destinations, %u byte packets ",
                msg->n_reports, msg->header->packet_size);

        /* print each of the test results */
        for ( i = 0; i < msg->n_reports; i++ ) {
            item = msg->reports[i];

            printf("%s", item->name);
            inet_ntop(item->family, item->address.data, addrstr, INET6_ADDRSTRLEN);
            printf(" (%s)", addrstr);

            if ( item->has_rtt ) {
                printf(" %dus", item->rtt);
            } else {
                printf(" missing");
            }
            printf("\n");
        }
        printf("\n");

        amplet2__foo__report__free_unpacked(msg, NULL);
    }



## 4. Create the Makefile that will build the test

Tests are expected to be built using standard automake tools and need to
provide a ``Makefile.am`` that can be used to generate the actual Makefile.
This should include a rule to build the standalone test binary, the test shared
library, and the generated protocol buffer code.

The ``Makefile.am`` for an example test called ``foo`` might look something
like this:


    EXTRA_DIST=*.h foo.proto
    SUBDIRS= . test
    BUILT_SOURCES=foo.pb-c.c
    CLEANFILES=foo.pb-c.c foo.pb-c.h

    testdir=$(libdir)/$(PACKAGE)/tests

    bin_PROGRAMS=amp-foo
    amp_foo_SOURCES=../testmain.c
    amp_foo_LDADD=foo.la -L../../common/ -lamp -lprotobuf-c -lunbound -lwandevent
    amp_foo_LDFLAGS=-Wl,--no-as-needed

    test_LTLIBRARIES=foo.la
    foo_la_SOURCES=foo.c
    nodist_foo_la_SOURCES=foo.pb-c.c
    foo_la_LDFLAGS=-module -avoid-version -L../../common/ -lamp -lprotobuf-c -lwandevent

    INCLUDES=-I../ -I../../common/

    foo.pb-c.c: Makefile
            protoc-c --c_out=. foo.proto
                    protoc --python_out=../python/ampsave/tests/ foo.proto


To get built by the build system you will also need to:
 * add your test directory to the ``SUBDIRS`` variable in
   ``src/tests/Makefile.am``
 * add the test Makefile to the ``AC_CONFIG_FILES`` list in ``configure.ac``
 * add a conditional check for compiling the test using the ``AC_ARG_ENABLE``
   and ``AM_CONDITIONAL`` commands in ``configure.ac``



## 5. Create the python parser that will unpack the test result data

When the ``nntsc`` server receives a test result it needs to understand how to
treat the data. The ``.proto`` file describes the format of the contents, but
sometimes extra work needs to be done to put the raw data into a useful format
for storing in the database (e.g. converting types, making human readable
strings, etc) - this is the job of the ``ampsave`` parsers. You will need to
create a python file in ``src/tests/python/ampsave/tests/`` that contains a
``get_data(data)`` function that reads the data and converts it into a useful
structure for your test type. This might mean a dictionary or list of
dictionaries, depending on how many destinations the test can have.

An example file for the ``foo`` test might look something like this:

    import ampsave.tests.foo_pb2
    from ampsave.common import getPrintableAddress

    def get_data(data):
        results = []
        msg = ampsave.tests.foo_pb2.Report()
        msg.ParseFromString(data)

        for i in msg.reports:
            results.append(
                {
                    "target": i.name if len(i.name) > 0 else "unknown",
                    "address": getPrintableAddress(i.family, i.address),
                    "rtt": i.rtt if i.HasField("rtt") else None,
                }
            )

        return results
