#include <sys/prctl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

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

#include "youtube.h"
#include "youtube.pb-c.h"


/*
 * Based around the example headless code in chromium:
 *      chromium/src/headless/app/headless_example.cc
 */
class HeadlessTest : public headless::HeadlessWebContents::Observer,
                        public headless::page::Observer {
 public:
     HeadlessTest(headless::HeadlessBrowser* browser,
             headless::HeadlessWebContents* web_contents);
     ~HeadlessTest() override;

     void DevToolsTargetReady() override;
     void OnJavascriptDialogOpening(
             const headless::page::JavascriptDialogOpeningParams& params) override;

     void OnEvaluateResult(
             std::unique_ptr<headless::runtime::EvaluateResult> result);
     void OnVideoItemFetched(
             std::unique_ptr<headless::runtime::GetPropertiesResult> result);
     void UpdateYoutubeTiming(struct YoutubeTiming *item,
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
          outstanding_(0) {
    web_contents_->AddObserver(this);

    base::CommandLine *commandline = base::CommandLine::ForCurrentProcess();

    /* TODO load the page from a local file */
    url_ = std::string("https://wand.net.nz/~brendonj/yt.html");
    //url_ = std::string("file://" AMP_EXTRA_DIRECTORY "/yt.html") +

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



/*
 * Remove observers and devtools targets before shutting the browser down.
 */
HeadlessTest::~HeadlessTest() {
    /*
     * Note that we shut down the browser last, because it owns objects such
     * as the web contents which can no longer be accessed after the browser
     * is gone.
     */
    devtools_client_->GetPage()->RemoveObserver(this);
    web_contents_->GetDevToolsTarget()->DetachClient(devtools_client_.get());
    web_contents_->RemoveObserver(this);
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
    devtools_client_->GetPage()->AddObserver(this);
    devtools_client_->GetPage()->Enable();

    /* load the actual page */
    devtools_client_->GetPage()->Navigate(url_);
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
        printf("Failed to evaluate: %s\n",
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
            printf("ignoring unknown response of type %s\n",classname.c_str());
        }
    } else {
        printf("failed to get objectid\n");
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
        printf("exception when fetching properties\n");
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
            } else {
                /* TODO load the "timeline" array */
            }
        }
    }

    if ( --outstanding_ <= 0 ) {
        delete g_example;
        g_example = nullptr;
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
    } else if ( name == "unknown_time" ) {
        item->unknown_time = GetInteger(value);
    } else if ( name == "reported_duration" ) {
        item->reported_duration = GetDouble(value);
    }
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
    context_builder.SetUserAgent(
            "AMP YouTube test agent (Chromium commit c850f7a8cb92c402)");
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
    base::CommandLine::Init(argc, argv);
    base::CommandLine *commandline = base::CommandLine::ForCurrentProcess();

    if ( !commandline->HasSwitch("type") ) {
        /*
         * if --type isn't set then this is the first process, clobber
         * /proc/self/exe with the standalone test binary so that when
         * chromium forks to run zygote processes they actually run
         * (rather than trying to run amplet2 and failing with bad arguments).
         */
        int fd;
        /* XXX where to load the binary from? try a few places? */
        if ( (fd=open("/bin/amp-youtube", 0, "r")) < 0 ) {
            printf("Failed XXX");
            exit(-1);
        }
        if ( prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0) < 0 ) {
            printf("prctl failed: %s\n", strerror(errno));
            exit(-1);
        }
    }

    headless::RunChildProcessIfNeeded(argc, argv);
    headless::HeadlessBrowser::Options::Builder builder(argc, argv);
    builder.SetWindowSize(gfx::Size(1920, 1080));
    headless::HeadlessBrowserMain(builder.Build(),
            base::Bind(&OnHeadlessBrowserStarted));

    return youtube;
}
