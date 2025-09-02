"""
By:liang-work
使用使用dnspython库工作，函数query_dns_record()查询域的A/AAAA/CNAME等记录。使用whois_query()进行whois查询
请手动安装dnspython库！
"""

import re
import socket
import dns.resolver

def is_valid_domain(domain):
    # 排除 IPv4 地址
    ipv4_pattern = re.compile(
        r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    )
    if ipv4_pattern.match(domain):
        return False

    # 排除 IPv6 地址
    ipv6_pattern = re.compile(
        r"^(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,7}:$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}$|"
        r"^(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}$|"
        r"^[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}$|"
        r"^:(?::[A-Fa-f0-9]{1,4}){1,7}$"
    )
    if ipv6_pattern.match(domain):
        return False

    # 正则表达式验证域名格式
    domain_pattern = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*(?<!-)$"
    )
    # 检查域名长度
    if len(domain) > 253:
        return False
    # 检查域名格式
    return bool(domain_pattern.match(domain))

def clean_domain(domain):
    # 去除域名前的 "https://" 或 "http://"
    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]
    # 去除域名后的 "/" 如果有的话
    domain = domain.rstrip('/')
    # 检查是否为有效域名
    if not is_valid_domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain

def query_dns_record(domain, record_type, tcp=False): # 也可以直接调用 query_dns_record 查询
    """
    查询域名的DNS记录
    :param domain: 域名
    :param record_type: DNS记录类型
    :param tcp: 是否使用TCP查询
    :return: 查询结果
    """
    domain = clean_domain(domain)  # 清理域名
    try:
        back_value = []
        answers = dns.resolver.resolve(domain, record_type, tcp=tcp)
        print("Non-authoritative answers")
        for rdata in answers:
            if record_type == "A" or record_type == "AAAA":
                back_value.append(rdata.address)
            elif record_type == "CNAME":
                back_value.append(rdata.target)
            elif record_type == "NS" or  record_type == "MX":
                back_value.append(str(rdata))
        return back_value
    except dns.resolver.NoAnswer:
        return "NoAnswer"
    except dns.resolver.NXDOMAIN:
        return "NotFoundNS"
    except Exception as e:
        return False

def whois_query(domain):
    """
    查询域名的Whois信息
    :param domain: 域名
    :return: Whois信息
    """
    try:
        # 尝试找到Whois服务器，先从最长的子域开始查询
        whois_server = get_whois_server(domain)

        # 连接到Whois服务器
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((whois_server, 43))
            s.sendall((domain + "\r\n").encode('ascii'))

            # 接收Whois服务器的响应
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data

            return response.decode('utf-8')
    except Exception as e:
        return f"查询失败: {e}"


def get_whois_server(domain):
    # 将域名分割成各个部分
    parts = domain.split('.')
    # 从最长的子域开始查找Whois服务器
    for i in range(len(parts)):
        # 组合成查询的域名部分
        tld = '.'.join(parts[i:])
        # 查找Whois服务器
        whois_server = whois_servers.get(tld)
        if whois_server:
            return whois_server
    # 如果没有找到特定的Whois服务器，则使用通用的Whois服务器
    return "whois.iana.org"


whois_servers = {
    "ac": "whois.nic.ac",
    "ad": "whois.ripe.net",
    "ae": "whois.aeda.net.ae",
    "aero": "whois.aero",
    "af": "whois.nic.af",
    "ag": "whois.nic.ag",
    "ai": "whois.ai",
    "al": "whois.ripe.net",
    "am": "whois.amnic.net",
    "as": "whois.nic.as",
    "asia": "whois.nic.asia",
    "at": "whois.nic.at",
    "au": "whois.aunic.net",
    "aw": "whois.nic.aw",
    "ax": "whois.ax",
    "az": "whois.ripe.net",
    "ba": "whois.ripe.net",
    "bar": "whois.nic.bar",
    "be": "whois.dns.be",
    "berlin": "whois.nic.berlin",
    "best": "whois.nic.best",
    "bg": "whois.register.bg",
    "bi": "whois.nic.bi",
    "biz": "whois.neulevel.biz",
    "bj": "www.nic.bj",
    "bo": "whois.nic.bo",
    "br": "whois.nic.br",
    "br.com": "whois.centralnic.com",
    "bt": "whois.netnames.net",
    "bw": "whois.nic.net.bw",
    "by": "whois.cctld.by",
    "bz": "whois.belizenic.bz",
    "bzh": "whois-bzh.nic.fr",
    "ca": "whois.cira.ca",
    "cat": "whois.cat",
    "cc": "whois.nic.cc",
    "cd": "whois.nic.cd",
    "ceo": "whois.nic.ceo",
    "cf": "whois.dot.cf",
    "ch": "whois.nic.ch",
    "ci": "whois.nic.ci",
    "ck": "whois.nic.ck",
    "cl": "whois.nic.cl",
    "cloud": "whois.nic.cloud",
    "club": "whois.nic.club",
    "cn": "whois.cnnic.net.cn",
    "cn.com": "whois.centralnic.com",
    "co": "whois.nic.co",
    "co.nl": "whois.co.nl",
    "com": "whois.verisign-grs.com",
    "coop": "whois.nic.coop",
    "cx": "whois.nic.cx",
    "cy": "whois.ripe.net",
    "cz": "whois.nic.cz",
    "de": "whois.denic.de",
    "dk": "whois.dk-hostmaster.dk",
    "dm": "whois.nic.cx",
    "dz": "whois.nic.dz",
    "ec": "whois.nic.ec",
    "edu": "whois.educause.net",
    "ee": "whois.tld.ee",
    "eg": "whois.ripe.net",
    "es": "whois.nic.es",
    "eu": "whois.eu",
    "eu.com": "whois.centralnic.com",
    "eus": "whois.nic.eus",
    "fi": "whois.fi",
    "fo": "whois.nic.fo",
    "fr": "whois.nic.fr",
    "gb": "whois.ripe.net",
    "gb.com": "whois.centralnic.com",
    "gb.net": "whois.centralnic.com",
    "qc.com": "whois.centralnic.com",
    "ge": "whois.ripe.net",
    "gg": "whois.gg",
    "gi": "whois2.afilias-grs.net",
    "gl": "whois.nic.gl",
    "gm": "whois.ripe.net",
    "gov": "whois.nic.gov",
    "gr": "whois.ripe.net",
    "gs": "whois.nic.gs",
    "gy": "whois.registry.gy",
    "hamburg": "whois.nic.hamburg",
    "hiphop": "whois.uniregistry.net",
    "hk": "whois.hknic.net.hk",
    "hm": "whois.registry.hm",
    "hn": "whois2.afilias-grs.net",
    "host": "whois.nic.host",
    "hr": "whois.dns.hr",
    "ht": "whois.nic.ht",
    "hu": "whois.nic.hu",
    "hu.com": "whois.centralnic.com",
    "id": "whois.pandi.or.id",
    "ie": "whois.domainregistry.ie",
    "il": "whois.isoc.org.il",
    "im": "whois.nic.im",
    "in": "whois.inregistry.net",
    "info": "whois.afilias.info",
    "ing": "domain-registry-whois.l.google.com",
    "ink": "whois.centralnic.com",
    "int": "whois.isi.edu",
    "io": "whois.nic.io",
    "iq": "whois.cmc.iq",
    "ir": "whois.nic.ir",
    "is": "whois.isnic.is",
    "it": "whois.nic.it",
    "je": "whois.je",
    "jobs": "jobswhois.verisign-grs.com",
    "jp": "whois.jprs.jp",
    "ke": "whois.kenic.or.ke",
    "kg": "whois.domain.kg",
    "ki": "whois.nic.ki",
    "kr": "whois.kr",
    "kz": "whois.nic.kz",
    "la": "whois2.afilias-grs.net",
    "li": "whois.nic.li",
    "london": "whois.nic.london",
    "lt": "whois.domreg.lt",
    "lu": "whois.restena.lu",
    "lv": "whois.nic.lv",
    "ly": "whois.lydomains.com",
    "ma": "whois.iam.net.ma",
    "mc": "whois.ripe.net",
    "md": "whois.nic.md",
    "me": "whois.nic.me",
    "mg": "whois.nic.mg",
    "mil": "whois.nic.mil",
    "mk": "whois.ripe.net",
    "ml": "whois.dot.ml",
    "mo": "whois.monic.mo",
    "mobi": "whois.dotmobiregistry.net",
    "ms": "whois.nic.ms",
    "mt": "whois.ripe.net",
    "mu": "whois.nic.mu",
    "museum": "whois.museum",
    "mx": "whois.nic.mx",
    "my": "whois.mynic.net.my",
    "mz": "whois.nic.mz",
    "na": "whois.na-nic.com.na",
    "name": "whois.nic.name",
    "nc": "whois.nc",
    "net": "whois.verisign-grs.com",
    "nf": "whois.nic.cx",
    "ng": "whois.nic.net.ng",
    "nl": "whois.domain-registry.nl",
    "no": "whois.norid.no",
    "no.com": "whois.centralnic.com",
    "nu": "whois.nic.nu",
    "nz": "whois.srs.net.nz",
    "om": "whois.registry.om",
    "ong": "whois.publicinterestregistry.net",
    "ooo": "whois.nic.ooo",
    "org": "whois.pir.org",
    "paris": "whois-paris.nic.fr",
    "pe": "kero.yachay.pe",
    "pf": "whois.registry.pf",
    "pics": "whois.uniregistry.net",
    "pl": "whois.dns.pl",
    "pm": "whois.nic.pm",
    "pr": "whois.nic.pr",
    "press": "whois.nic.press",
    "pro": "whois.registrypro.pro",
    "pt": "whois.dns.pt",
    "pub": "whois.unitedtld.com",
    "pw": "whois.nic.pw",
    "qa": "whois.registry.qa",
    "re": "whois.nic.re",
    "ro": "whois.rotld.ro",
    "rs": "whois.rnids.rs",
    "ru": "whois.tcinet.ru",
    "sa": "saudinic.net.sa",
    "sa.com": "whois.centralnic.com",
    "sb": "whois.nic.net.sb",
    "sc": "whois2.afilias-grs.net",
    "se": "whois.nic-se.se",
    "se.com": "whois.centralnic.com",
    "se.net": "whois.centralnic.com",
    "sg": "whois.nic.net.sg",
    "sh": "whois.nic.sh",
    "si": "whois.arnes.si",
    "sk": "whois.sk-nic.sk",
    "sm": "whois.nic.sm",
    "st": "whois.nic.st",
    "so": "whois.nic.so",
    "su": "whois.tcinet.ru",
    "sx": "whois.sx",
    "sy": "whois.tld.sy",
    "tc": "whois.adamsnames.tc",
    "tel": "whois.nic.tel",
    "tf": "whois.nic.tf",
    "th": "whois.thnic.net",
    "tj": "whois.nic.tj",
    "tk": "whois.nic.tk",
    "tl": "whois.domains.tl",
    "tm": "whois.nic.tm",
    "tn": "whois.ati.tn",
    "to": "whois.tonic.to",
    "top": "whois.nic.top",
    "tp": "whois.domains.tl",
    "tr": "whois.nic.tr",
    "travel": "whois.nic.travel",
    "tw": "whois.twnic.net.tw",
    "tv": "whois.nic.tv",
    "tz": "whois.tznic.or.tz",
    "ua": "whois.ua",
    "ug": "whois.co.ug",
    "uk": "whois.nic.uk",
    "uk.com": "whois.centralnic.com",
    "uk.net": "whois.centralnic.com",
    "ac.uk": "whois.ja.net",
    "gov.uk": "whois.ja.net",
    "us": "whois.nic.us",
    "us.com": "whois.centralnic.com",
    "uy": "nic.uy",
    "uy.com": "whois.centralnic.com",
    #"us.kg":"whois.us.kg", #不知道什么原因，无法连接服务器，查不了
    "uz": "whois.cctld.uz",
    "va": "whois.ripe.net",
    "vc": "whois2.afilias-grs.net",
    "ve": "whois.nic.ve",
    "vg": "ccwhois.ksregistry.net",
    "vu": "vunic.vu",
    "wang": "whois.nic.wang",
    "wf": "whois.nic.wf",
    "wiki": "whois.nic.wiki",
    "ws": "whois.website.ws",
    "xxx": "whois.nic.xxx",
    "xyz": "whois.nic.xyz",
    "yu": "whois.ripe.net",
    "za.com": "whois.centralnic.com"
}
