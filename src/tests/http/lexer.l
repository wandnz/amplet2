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
%}

%x script scriptbody noscript comment img dbquote squote linktag style dbquote_data squote_data
%%

"<!--"				{ yy_push_state(comment); };
<comment>[^-\n]*		{ /* eat anything that's not a '-' */ };
<comment>"-"[^->\n]*		{ /* eat up '-'s not followed by '-' '>' */ };
<comment>\n			{ };
<comment>"-"{2,}">"		{ yy_pop_state(); };

"<noscript>"			{ yy_push_state(noscript); };
<noscript>[^<\n]*		{ };
<noscript>"<"[^/<\n]*		{ };
<noscript>\n			{ /* do nothing */ };
<noscript>"</noscript>"		{ yy_pop_state(); };



"<script"			{ yy_push_state(script); };
<script>">"                     { yy_push_state(scriptbody); };
<script>[^s<>\n]*		{ /* eat all non 's' or angle bracket */ };
<script>\n			{ };
<script>"s"                     { /* eat up 's's not followed by 'r's */ };
<script>"src=\""                { yy_push_state(dbquote); };
<script>"src=\'"                { yy_push_state(squote); };
<script>"src=\"data:"           { yy_push_state(dbquote_data); };
<script>"src=\'data:"           { yy_push_state(squote_data); };

<scriptbody>[^<]*               { /* eat anything that's not a '<' */ };
<scriptbody>"<"[^/<\n]*         { /* eat any '<'s not followed by '/' */ };
<scriptbody>"</script>"         { yy_pop_state(); yy_pop_state(); };


"<img"				{ yy_push_state(img); };
<img>[^s>\n]*			{ /* eat anything that's not a '/' */ };
<img>\n				{ };
<img>">"			{ yy_pop_state(); };
<img>"s"                        { /* eat up 's's not followed by 'r's */ };
<img>"src=\""                   { yy_push_state(dbquote); };
<img>"src=\'"                   { yy_push_state(squote); };
<img>"src=\"data:"              { yy_push_state(dbquote_data); };
<img>"src=\'data:"              { yy_push_state(squote_data); };

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
					add_object(url, 0);
				    } else {
					yy_push_state(style);
                                    }
				};

<linktag>("rel=\""{CHAR}*"icon"{CHAR}*"\"") | \
    ("rel=\'"{CHAR}*"icon"{CHAR}*"\'") {

				    if ( url_index > 0 ) {
					add_object(url, 0);
				    } else {
					yy_push_state(style);
                                    }
				};

<linktag>">"			{ url_index = 0; yy_pop_state(); };

<dbquote>&#[0-9]{2,3};          {
                                    /* decode decimal encoded HTML characters */
                                    url[url_index++] = atoi(yytext+2);
                                }
<dbquote>#                      {
                                    /* end the url when a '#' is seen */
                                    url[url_index++] = '\0';
                                }
<dbquote>[^\"]{1}		{ url[url_index] = yytext[0]; url_index++; };
<dbquote>"\""			{
				    url[url_index] = '\0';
				    if ( yy_top_state() != linktag ) {
					url_index = 0;
					add_object(url, 0);
				    }
				    if ( yy_top_state() == style ) {
                                        yy_pop_state();
                                    }
                                    yy_pop_state();
				};

<squote>&#[0-9]{2,3};           {
                                    /* decode decimal encoded HTML characters */
                                    url[url_index++] = atoi(yytext+2);
                                }
<squote>#                       {
                                    /* end the url when a '#' is seen */
                                    url[url_index++] = '\0';
                                }
<squote>[^']{1}			{ url[url_index] = yytext[0]; url_index++; };
<squote>"'"			{
				    url[url_index] = '\0';
				    if ( yy_top_state() != linktag ) {
					url_index = 0;
					add_object(url, 0);
				    }
				    if ( yy_top_state() == style ) {
                                        yy_pop_state();
                                    }
                                    yy_pop_state();
				};

<dbquote_data>[^\"]{1}          { /* ignore everything except ending quote */};
<dbquote_data>"\""              { yy_pop_state(); }

<squote_data>[^']{1}            { /* ignore everything except ending quote */};
<squote_data>"'"                { yy_pop_state(); }


"</html>"			{ return 0; };
.|\n				{ /* ignore everything else */ }

%%



int yyerror(char *s) {
    fprintf(stderr, "%s\n", s);
    return 0;
}
