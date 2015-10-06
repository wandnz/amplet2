CHAR	    [a-zA-Z0-9_ ]

%option noyywrap stack nounput noinput always-interactive

%{
    #include <stdio.h>
    #include <string.h>
    #include "http.h"

    int yylex(void);
    int yyerror(char *s);

    static char url[MAX_URL_LEN];
    static int url_index = 0;

    static void parsed_complete_object(char *url);

    struct object_stats_t;
    struct server_stats_t;

    extern struct server_stats_t *add_object(char *url, int parse);
    extern void* pipeline_next_object(CURLM *multi, struct server_stats_t *server);
    extern CURLM *multi;

%}

%x script scriptbody noscript comment img dbquote squote linktag style
%%

"<!--"				{ yy_push_state(comment); };
<comment>[^-\n]*		{ /* eat anything that's not a '-' */ };
<comment>"-"[^->\n]*		{ /* eat up '-'s not followed by '-' '>' */ };
<comment>\n			{ };
<comment>"-"{2,}">"		{ yy_pop_state(); };

"<noscript>"			{ yy_push_state(noscript); };
<noscript>[^<\n]*		{ };
<noscript>"<"[^/\n]*		{ };
<noscript>\n			{ /* do nothing */ };
<noscript>"</noscript>"		{ yy_pop_state(); };



"<script"			{ yy_push_state(script); };
<script>">"                     { yy_push_state(scriptbody); };
<script>[^s<>\n]*		{ /* eat all non 's' or angle bracket */ };
<script>\n			{ };
<script,img>"s"			{ /* eat up 's's not followed by 'r's */ };
<script,img>"src=\""		{ yy_push_state(dbquote); };
<script,img>"src=\'"		{ yy_push_state(squote); };

<scriptbody>[^<]*               { /* eat anything that's not a '<' */ };
<scriptbody>"<"[^/\n]*          { /* eat any '<'s not followed by '/' */ };
<scriptbody>"</script>"         { yy_pop_state(); yy_pop_state(); };


"<img"				{ yy_push_state(img); };
<img>[^s>\n]*			{ /* eat anything that's not a '/' */ };
<img>\n				{ };
<img>">"			{ yy_pop_state(); };

"<link"				{ yy_push_state(linktag); };
<linktag,style>[^hr>\n]*	{ /* anything that isnt href,rel or endtag */ };
<linktag,style>"h"[^r>\n]	{ /* h that doesn't start href */ };
<linktag,style>"href=\""	{ yy_push_state(dbquote); };
<linktag,style>"href=\'"	{ yy_push_state(squote); };
<linktag,style>\n		{ };
<linktag,style>"r"		{ /* eat 'r' that isn't rel='stylesheet' */ };
<linktag,style>"h"		{ /* eat 'h' that isn't href= */ };

<linktag>("rel=\"stylesheet\"")|("rel=\'stylesheet\'") {

				    if ( url_index > 0 ) {
					parsed_complete_object(url);
				    } else {
					yy_push_state(style);
                                    }
				};

<linktag>("rel=\""{CHAR}*"icon"{CHAR}*"\"") | \
    ("rel=\'"{CHAR}*"icon"{CHAR}*"\'") {

				    if ( url_index > 0 ) {
					parsed_complete_object(url);
				    } else {
					yy_push_state(style);
                                    }
				};

<linktag>">"			{ url_index = 0; yy_pop_state(); };

<dbquote>[^\"]{1}		{ url[url_index] = yytext[0]; url_index++; };
<dbquote>"\""			{
				    url[url_index] = '\0';
				    if ( yy_top_state() != linktag ) {
					url_index = 0;
					parsed_complete_object(url);
				    }
				    if ( yy_top_state() == style ) {
                                        yy_pop_state();
                                    }
                                    yy_pop_state();
				};

<squote>[^']{1}			{ url[url_index] = yytext[0]; url_index++; };
<squote>"'"			{
				    url[url_index] = '\0';
				    if ( yy_top_state() != linktag ) {
					url_index = 0;
					parsed_complete_object(url);
				    }
				    if ( yy_top_state() == style ) {
                                        yy_pop_state();
                                    }
                                    yy_pop_state();
				};



"</html>"			{ return 0; };
.|\n				{ /* ignore everything else */ }

%%




static void parsed_complete_object(char *url) {
    struct server_stats_t *server;

    server = add_object(url, 0);

    if ( server != NULL ) {
	pipeline_next_object(multi, server);
    }
}

int yyerror(char *s) {
    fprintf(stderr, "%s\n", s);
    return 0;
}

