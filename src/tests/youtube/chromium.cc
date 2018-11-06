/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2018 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include "base/bind.h"
#include "base/memory/weak_ptr.h"
#include "base/command_line.h"
#include "ui/gfx/geometry/size.h"

#include "headless/public/devtools/domains/page.h"
#include "headless/public/devtools/domains/runtime.h"
#include "headless/public/devtools/domains/types_runtime.h"

#include "headless/public/headless_browser.h"
#include "headless/public/headless_devtools_client.h"
#include "headless/public/headless_devtools_target.h"
#include "headless/public/headless_web_contents.h"

#include "debug.h"
#include "youtube.h"
#include "youtube.pb-c.h"


/*
 * Based around the example headless code in chromium:
 *      chromium/src/headless/app/headless_example.cc
 */
class HeadlessTest : public headless::HeadlessWebContents::Observer,
                        public headless::page::ExperimentalObserver {
 public:
     HeadlessTest(headless::HeadlessBrowser* browser,
             headless::HeadlessWebContents* web_contents);
     ~HeadlessTest() override;

     void Shutdown();
     void DevToolsTargetReady() override;
     void OnFrameStoppedLoading(
             const headless::page::FrameStoppedLoadingParams& params) override;
     void OnFrameNavigated(
             const headless::page::FrameNavigatedParams& params) override;
     void OnJavascriptDialogOpening(
             const headless::page::JavascriptDialogOpeningParams& params) override;

     void OnEvaluateResult(
             std::unique_ptr<headless::runtime::EvaluateResult> result);
     void OnVideoItemFetched(
             std::unique_ptr<headless::runtime::GetPropertiesResult> result);
     void OnTimelineFetched(
             std::unique_ptr<headless::runtime::GetPropertiesResult> result);

     void UpdateYoutubeTiming(struct YoutubeTiming *item,
             std::string name, const base::Value *value);
     int UpdateTimeline(struct TimelineEvent *item,
             std::string name, const base::Value *value);
 private:

     /* The headless browser instance. Owned by the headless library */
     headless::HeadlessBrowser* browser_;
     /* Our tab. Owned by |browser_| */
     headless::HeadlessWebContents* web_contents_;
     /* The DevTools client used to control the tab */
     std::unique_ptr<headless::HeadlessDevToolsClient> devtools_client_;
     /* A helper for creating weak pointers to this class */
     base::WeakPtrFactory<HeadlessTest> weak_factory_;

     int navigation_ok_;
     int outstanding_;
     std::string url_;
};



namespace {
    HeadlessTest* g_example;
    struct YoutubeTiming *youtube = NULL;

    std::string GetString(const base::Value *value) {
        std::string string_value;
        if ( value->GetAsString(&string_value) ) {
            return string_value;
        }

        return NULL;
    }

    int GetInteger(const base::Value *value) {
        int integer_value;
        if ( value->GetAsInteger(&integer_value) ) {
            return integer_value;
        }

        return 0;
    }

    double GetDouble(const base::Value *value) {
        double double_value;
        if ( value->GetAsDouble(&double_value) ) {
            return double_value;
        }

        return 0;
    }
}



/*
 * Build a new headless web browser test framework and extract everything we
 * need for it from the command line.
 */
HeadlessTest::HeadlessTest(headless::HeadlessBrowser* browser,
                                 headless::HeadlessWebContents* web_contents)
        : browser_(browser),
          web_contents_(web_contents),
          devtools_client_(headless::HeadlessDevToolsClient::Create()),
          weak_factory_(this),
          navigation_ok_(0),
          outstanding_(0) {
    web_contents_->AddObserver(this);

    struct stat buf;
    base::CommandLine *commandline = base::CommandLine::ForCurrentProcess();

    /*
     * XXX I'd really like to load the page from a data:// URI but apparently
     * they don't support query parameters. We'd have to remove the ability
     * to choose the video, quality levels etc.
     * TODO investigate using devtools SetDocumentContent() to load the page,
     * will it run all the javascript etc? Instead of loading the page using
     * Navigate(), set it directly.
     */
    if ( stat(AMP_EXTRA_DIRECTORY "/yt.html", &buf) == 0 && buf.st_size > 0 ) {
        url_ = std::string("file://" AMP_EXTRA_DIRECTORY "/yt.html");
    } else {
        /* XXX temporary until a better solution is found */
        url_ = std::string("https://wand.net.nz/~brendonj/yt.html");
    }

    /*
     * TODO move this into an init() type function that gets explicitly
     * called so that we can then return errors gracefully from it?
     */
    if ( commandline->HasSwitch("youtube") ) {
        url_ += std::string("?video=") +
            commandline->GetSwitchValueASCII("youtube");

        if ( commandline->HasSwitch("quality") ) {
            url_ += std::string("&quality=") +
                commandline->GetSwitchValueASCII("quality");
        }
    }
}



HeadlessTest::~HeadlessTest() {}



/*
 * Remove observers and devtools targets before shutting the browser down.
 * Note that we shut down the browser last, because it owns objects such
 * as the web contents which can no longer be accessed after the browser
 * is gone.
 */
void HeadlessTest::Shutdown() {
    Log(LOG_DEBUG, "Shutting down browser");

    if ( !web_contents_ ) {
        Log(LOG_WARNING, "No web contents, skipping browser shutdown");
        return;
    }

    devtools_client_->GetPage()->Disable();
    devtools_client_->GetPage()->GetExperimental()->RemoveObserver(this);

    if ( web_contents_->GetDevToolsTarget() ) {
        web_contents_->GetDevToolsTarget()->DetachClient(devtools_client_.get());
    }

    web_contents_->RemoveObserver(this);
    web_contents_->Close();
    web_contents_ = nullptr;
    browser_->Shutdown();
}



/*
 * Browser tab is ready, attach a devtools client to it and trigger navigation.
 */
void HeadlessTest::DevToolsTargetReady() {
    web_contents_->GetDevToolsTarget()->AttachClient(devtools_client_.get());

    /*
     * Start observing events from DevTools's page domain. This lets us get
     * notified when the page has finished loading. Note that it is possible
     * the page has already finished loading by now. See
     * HeadlessShell::DevToolTargetReady for how to handle that case correctly.
     */
    devtools_client_->GetPage()->GetExperimental()->AddObserver(this);
    devtools_client_->GetPage()->Enable();

    /* load the actual page */
    devtools_client_->GetPage()->Navigate(url_);
}



/*
 * Part of a speculative fix for hung connections. After loading the test URL
 * it infrequently stalls rather than loading the youtube iframe API. On a
 * successful test no frame should stop loading until after we observe a
 * navigation to youtube. If this isn't the case, force a reload and try again.
 * TODO: find the root cause (is it our fault or chromium?)
 */
void HeadlessTest::OnFrameStoppedLoading(
        const headless::page::FrameStoppedLoadingParams& params) {
    if ( !navigation_ok_ ) {
        Log(LOG_WARNING, "Couldn't load YouTube iframe API, retrying");
        devtools_client_->GetPage()->Reload(
            headless::page::ReloadParams::Builder().SetIgnoreCache(1).Build());
    }
}



/*
 * Part of a speculative fix for hung connections. After loading the test URL
 * it infrequently stalls rather than loading the youtube iframe API. Set a
 * flag when we see navigation begin to a youtube URL.
 */
void HeadlessTest::OnFrameNavigated(
        const headless::page::FrameNavigatedParams& params) {
    Log(LOG_DEBUG, "Navigating to %s", params.GetFrame()->GetUrl().c_str());

    /* XXX this perhaps isn't as robust as it should be */
    if ( strncmp("https://www.youtube.com", params.GetFrame()->GetUrl().c_str(),
                strlen("https://www.youtube.com")) == 0 ) {
        navigation_ok_ = 1;
    }
}



/*
 * Javascript alert has fired, assume it means youtube test results are ready.
 *
 * Ideally there would be a nice way to signal that the video has finished
 * playing and results are ready for collection, but haven't found a better
 * mechanism yet. We can be fairly certain that our page isn't generating
 * any other javascript alerts, and youtube probably isn't either.
 */
void HeadlessTest::OnJavascriptDialogOpening(
        const headless::page::JavascriptDialogOpeningParams& params) {
    /* acknowledge the alert popup */
    devtools_client_->GetPage()->HandleJavaScriptDialog(1);

    /* query the javascript variable the youtube timing page creates */
    devtools_client_->GetRuntime()->Evaluate(
            "youtuberesults;",
            base::Bind(&HeadlessTest::OnEvaluateResult,
                weak_factory_.GetWeakPtr()));
}



/*
 * Callback for dealing with the results of Evaluate().
 *
 * In this case, specifically unpacking the top level object around the
 * youtube timing results so that we can query for the actual values.
 */
void HeadlessTest::OnEvaluateResult(
        std::unique_ptr<headless::runtime::EvaluateResult> result) {

    if ( result->HasExceptionDetails() ) {
        Log(LOG_ERR, "Failed to evaluate: %s",
                result->GetExceptionDetails()->GetText().c_str());
        return;
    }

    std::unique_ptr<base::Value> value = result->Serialize();
    const base::DictionaryValue *dict_value;

    if ( value->GetAsDictionary(&dict_value) ) {
        const base::DictionaryValue *out_value;
        std::string string_value, classname;
        dict_value->GetDictionary("result", &out_value);
        /* get object id from the results dictionary */
        out_value->GetString("className", &classname);
        if ( classname == "Object" ) {
            /* get the timings from the properties of the result object */
            out_value->GetString("objectId", &string_value);
            devtools_client_->GetRuntime()->GetProperties(
                    string_value,
                    base::Bind(&HeadlessTest::OnVideoItemFetched,
                        weak_factory_.GetWeakPtr()));
            ++outstanding_;
        } else {
            Log(LOG_DEBUG, "Ignoring unknown response of type %s",
                    classname.c_str());
        }
    } else {
        Log(LOG_WARNING, "Failed to get objectid");
    }
}



/*
 * Callback for dealing with results of GetProperties() on the timeline array.
 *
 * Extracts each of the useful items from the response, fetching deeper
 * layers as required and stores them in a linked list under the global
 * youtube timing object.
 */
void HeadlessTest::OnTimelineFetched(
        std::unique_ptr<headless::runtime::GetPropertiesResult> result) {

    int fields = 0;

    if (result->HasExceptionDetails()) {
        Log(LOG_ERR, "Exception when fetching properties");
        if ( --outstanding_ <= 0 ) {
            Shutdown();
        }
        return;
    }

    assert(youtube);

    struct TimelineEvent *timeline =
        (struct TimelineEvent*)calloc(1, sizeof(struct TimelineEvent));

    const std::vector<std::unique_ptr<headless::runtime::PropertyDescriptor>>*
        properties = result->GetResult();

    for ( std::vector<std::unique_ptr<headless::runtime::PropertyDescriptor>>::const_iterator it = properties->begin(); it != properties->end(); ++it ) {

        if ( (*it)->HasValue() ) {
            const headless::runtime::RemoteObject *obj;
            obj = (*it)->GetValue();
            if ( obj->GetType() ==
                    headless::runtime::RemoteObjectType::STRING ||
                    obj->GetType() ==
                    headless::runtime::RemoteObjectType::NUMBER ) {

                /* OR the fields together to make sure we have all of them */
                fields |= UpdateTimeline(timeline, (*it)->GetName(),
                        obj->GetValue());
            } else if ( obj->GetType() ==
                    headless::runtime::RemoteObjectType::OBJECT ) {
                std::unique_ptr<base::Value> value = obj->Serialize();
                /* dig into the elements within the dictionary item */
                if ( value.get()->type() == base::Value::Type::DICTIONARY ) {
                    std::string string_value;
                    base::DictionaryValue *dict_value;
                    value->GetAsDictionary(&dict_value);
                    dict_value->GetString("objectId", &string_value);
                    devtools_client_->GetRuntime()->GetProperties(
                            string_value,
                            base::Bind(&HeadlessTest::OnTimelineFetched,
                                weak_factory_.GetWeakPtr()));
                    ++outstanding_;
                }
            } else {
            }
        }
    }

    /* check that the required fields are filled in */
    if ( (fields & 0x3) == 0x3 ) {
        /* append it to the list of events */
        if ( youtube->timeline == NULL ) {
            youtube->timeline = timeline;
        } else {
            struct TimelineEvent *tmp = youtube->timeline;
            while ( tmp->next != NULL ) {
                tmp = tmp->next;
            }
            tmp->next = timeline;
        }

        youtube->event_count++;
    }

    if ( --outstanding_ <= 0 ) {
        Shutdown();
    }
}



/*
 * Callback for dealing with results of GetProperties() on the timings object.
 *
 * Extracts each of the useful items from the response dictionary and stores
 * them all together in the global youtube timing object.
 */
void HeadlessTest::OnVideoItemFetched(
        std::unique_ptr<headless::runtime::GetPropertiesResult> result) {

    if ( result->HasExceptionDetails() ) {
        Log(LOG_ERR, "Exception when fetching properties\n");
        if ( --outstanding_ <= 0 ) {
            Shutdown();
        }
        return;
    }

    assert(youtube == NULL);

    youtube = (struct YoutubeTiming*) calloc(1, sizeof(struct YoutubeTiming));

    const std::vector<std::unique_ptr<headless::runtime::PropertyDescriptor>>*
        properties = result->GetResult();

    for ( std::vector<std::unique_ptr<headless::runtime::PropertyDescriptor>>::const_iterator it = properties->begin(); it != properties->end(); ++it ) {

        if ( (*it)->HasValue() ) {
            const headless::runtime::RemoteObject *obj;
            obj = (*it)->GetValue();
            if ( obj->GetType() ==
                    headless::runtime::RemoteObjectType::STRING ||
                    obj->GetType() ==
                    headless::runtime::RemoteObjectType::NUMBER ) {

                UpdateYoutubeTiming(youtube, (*it)->GetName(),obj->GetValue());
            } else if ( obj->GetType() ==
                    headless::runtime::RemoteObjectType::OBJECT ) {
                /* load the "timeline" array */
                std::unique_ptr<base::Value> value = obj->Serialize();
                if ( value.get()->type() == base::Value::Type::DICTIONARY ) {
                    std::string string_value;
                    base::DictionaryValue *dict_value;
                    value->GetAsDictionary(&dict_value);
                    dict_value->GetString("objectId", &string_value);
                    devtools_client_->GetRuntime()->GetProperties(
                            string_value,
                            base::Bind(&HeadlessTest::OnTimelineFetched,
                                weak_factory_.GetWeakPtr()));
                            ++outstanding_;
                }
            }
        }
    }

    if ( --outstanding_ <= 0 ) {
        Shutdown();
    }
}



/*
 * Extract a timing value and store it in the youtube timing object.
 */
void HeadlessTest::UpdateYoutubeTiming(
        struct YoutubeTiming *item,
        std::string name,
        const base::Value *value) {

    assert(item);
    assert(value);

    if ( name == "video" ) {
        item->video = strdup(GetString(value).c_str());
    } else if ( name == "title" ) {
        item->title = strdup(GetString(value).c_str());
    } else if ( name == "quality" ) {
        std::string quality = GetString(value);
        if ( quality == "default" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__DEFAULT;
        } else if ( quality == "small" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__SMALL;
        } else if ( quality == "medium" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__MEDIUM;
        } else if ( quality == "large" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__LARGE;
        } else if ( quality == "hd720" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HD720;
        } else if ( quality == "hd1080" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HD1080;
        } else if ( quality == "hd1440" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HD1440;
        } else if ( quality == "hd2160" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HD2160;
        } else if ( quality == "highres" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HIGHRES;
        } else {
            item->quality = AMPLET2__YOUTUBE__QUALITY__UNKNOWN;
        }
    } else if ( name == "initial_buffering" ) {
        item->initial_buffering = GetInteger(value);
    } else if ( name == "playing_time" ) {
        item->playing_time = GetInteger(value);
    } else if ( name == "stall_time" ) {
        item->stall_time = GetInteger(value);
    } else if ( name == "stall_count" ) {
        item->stall_count = GetInteger(value);
    } else if ( name == "total_time" ) {
        item->total_time = GetInteger(value);
    } else if ( name == "pre_time" ) {
        item->pre_time = GetInteger(value);
    } else if ( name == "reported_duration" ) {
        item->reported_duration = GetInteger(value);
    }
}



/*
 * Extract a timeline value and store it in the timeline object.
 *
 * Returns a flag describing the sort of value that was extracted so that
 * the parent can check all the required fields were found.
 */
int HeadlessTest::UpdateTimeline(
        struct TimelineEvent *item,
        std::string name,
        const base::Value *value) {

    assert(item);
    assert(value);

    if ( name == "timestamp" ) {
        item->timestamp = GetInteger(value);
        return 0x1;
    }

    if ( name == "event" ) {
        std::string event = GetString(value);

        if ( event == "ready" ) {
            item->type = AMPLET2__YOUTUBE__EVENT_TYPE__READY;
        } else if ( event == "unstarted" ) {
            item->type = AMPLET2__YOUTUBE__EVENT_TYPE__UNSTARTED;
        } else if ( event == "buffering" ) {
            item->type = AMPLET2__YOUTUBE__EVENT_TYPE__BUFFERING;
        } else if ( event == "quality" ) {
            item->type = AMPLET2__YOUTUBE__EVENT_TYPE__QUALITY;
        } else if ( event == "playing" ) {
            item->type = AMPLET2__YOUTUBE__EVENT_TYPE__PLAYING;
        } else if ( event == "ended" ) {
            item->type = AMPLET2__YOUTUBE__EVENT_TYPE__ENDED;
        } else {
            item->type = AMPLET2__YOUTUBE__EVENT_TYPE__UNKNOWN_EVENT;
        }

        return 0x2;
    }

    if ( name == "quality" ) {
        std::string quality = GetString(value);

        if ( quality == "default" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__DEFAULT;
        } else if ( quality == "small" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__SMALL;
        } else if ( quality == "medium" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__MEDIUM;
        } else if ( quality == "large" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__LARGE;
        } else if ( quality == "hd720" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HD720;
        } else if ( quality == "hd1080" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HD1080;
        } else if ( quality == "hd1440" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HD1440;
        } else if ( quality == "hd2160" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HD2160;
        } else if ( quality == "highres" ) {
            item->quality = AMPLET2__YOUTUBE__QUALITY__HIGHRES;
        } else {
            item->quality = AMPLET2__YOUTUBE__QUALITY__UNKNOWN;
        }

        return 0x4;
    }

    return 0;
}



/*
 * Callback used when the browser is "started" (bit of a vague term).
 *
 * Creates a context within the browser, which contains the tab and the
 * tab configuration. We only use a single tab.
 */
void OnHeadlessBrowserStarted(headless::HeadlessBrowser* browser) {
    /* create browser context (user profile, cookies, local storage etc */
    headless::HeadlessBrowserContext::Builder context_builder =
        browser->CreateBrowserContextBuilder();

    /* set incognito so profile information isn't written to disk */
    context_builder.SetIncognitoMode(true);

    /* XXX SetHostResolverRules, etc */

    /* construct the context and set it as default */
    headless::HeadlessBrowserContext* browser_context = context_builder.Build();
    browser->SetDefaultBrowserContext(browser_context);

    /* open a tab in the newly created browser context */
    headless::HeadlessWebContents::Builder tab_builder(
            browser_context->CreateWebContentsBuilder());

    /* create instance of the application */
    headless::HeadlessWebContents* web_contents = tab_builder.Build();

    g_example = new HeadlessTest(browser, web_contents);
}



/*
 * Entry point for the test, exported as extern C for AMP to call into.
 */
void *cpp_main(int argc, const char *argv[]) {
    int nullfd;
    base::CommandLine::Init(argc, argv);
    base::CommandLine *commandline = base::CommandLine::ForCurrentProcess();

    if ( !commandline->HasSwitch("debug") ) {
        /* redirect stderr, as chromium is quite noisy and it is distracting */
        if ( (nullfd = open("/dev/null", O_WRONLY)) < 0 ) {
            Log(LOG_ERR, "Failed to open /dev/null for redirect: %s",
                    strerror(errno));
            exit(EXIT_FAILURE);
        }

        if ( dup2(nullfd, STDERR_FILENO) < 0 ) {
            Log(LOG_ERR, "Failed to redirect stderr: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }

#if 0
    /*
     * XXX this works in a docker but not on a real computer? Seems to be
     * because:
     *
     * "one needs to unmap all existing executable memory areas,
     * including those created by the kernel itself (for example the
     * kernel usually creates at least one executable memory area
     * for the ELF .text section)."
     *
     * which is all well and good, but unhelpful without more information.
     * My interpretation of that just leads to segfaults. Hopefully using
     * a single process isn't too different to multiple processes.
     */
    /* don't do any of this when doing standalone test? */
    if ( !commandline->HasSwitch("type") ) {
        int fd;
        char linkname[PATH_MAX+1];
        char *binary;

        /*
         * if --type isn't set then this is the first process, clobber
         * /proc/self/exe with the standalone test binary so that when
         * chromium forks to run zygote processes they actually run
         * (rather than trying to run amplet2 and failing with bad arguments).
         * Try to find the test binary in:
         *  - the same location as the currently executing binary
         *  - TODO the current directory?
         *  - TODO anywhere else?
         */

        memset(linkname, 0, sizeof(linkname));

        if ( readlink("/proc/self/exe", linkname, PATH_MAX) < 0 ) {
            printf("Failed readlink: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if ( asprintf(&binary, "%s/amp-youtube", dirname(linkname)) < 0 ) {
            printf("asprintf failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if ( (fd=open(binary, 0, "r")) < 0 ) {
            printf("open failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if ( prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0) < 0 ) {
            printf("prctl failed: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }
    }
#endif

    headless::RunChildProcessIfNeeded(argc, argv);
    headless::HeadlessBrowser::Options::Builder builder(argc, argv);
    builder.SetWindowSize(gfx::Size(1920, 1080));

    if ( commandline->HasSwitch("useragent") ) {
        /* TODO add a few pre-configured user agents? */
        std::string agent = commandline->GetSwitchValueASCII("useragent");
        builder.SetUserAgent(agent);
    }
    /* TODO see also: SetDisableSandbox(true) */

    Log(LOG_DEBUG, "Starting headless chromium browser");

    headless::HeadlessBrowserMain(builder.Build(),
            base::Bind(&OnHeadlessBrowserStarted));

    Log(LOG_DEBUG, "Finished with headless chromium browser");

    return youtube;
}
