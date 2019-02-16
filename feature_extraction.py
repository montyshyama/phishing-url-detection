#1 --> phishing
#0 --> suspicious
#-1 --> legitimate

import re
from tldextract import extract #this contains extract(url) function
import ssl, socket
import whois
from datetime import datetime
import time
from bs4 import BeautifulSoup
import requests
import html.parser
import pythonwhois
from googlesearch import search

def using_ip(url):
	match = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", url)
	if match:
		#print (match)
		return 1
	else:
		return -1

def long_url(url):
	if len(url)<54:
		return -1
	elif len(url) >= 54 and len(url) <= 75:
		return 0
	else:
		return 1

def shortening_services(url):
	match=re.findall('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
	if match:
		return 1
	else:
		return -1

def having_at(url):
	match = re.search('@', url)
	if match:
		return 1
	else:
		return -1

def redirecting_double_slash(url):
    try:
        list = [x.start(0) for x in re.finditer('//', url)]
        if list[len(list)-1] > 6:
            return 1
        else:
            return -1
    except:
        return 0

def prefix_suffix(url, subdomain, domain, suffix):
    #subdomain, domain, suffix = extract(url)
    if domain.count('-'):
        return 1
    else:
        return -1

def dots_in_domain(url, subdomain, domain, suffix):
    #ubdomain, domain, suffix = extract(url)
    if subdomain.count('.') == 0:
        return -1
    elif subdomain.count('.') == 1:
        return 0
    else:
        return 1

def https(url, subdomain, domain, suffix): #
    try:
        match = re.search('https', url)
        if match:
            usehttps = 1
        else:
            usehttps = 0
        #return usehttps
        #subdomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        issued_by = str(issuer['commonName'])
        issued_by = issued_by.split()
        if(issued_by[0] == "Network" or issued_by == "Deutsche"):
            issued_by = issued_by[0] + " " + issued_by[1]
        else:
            issued_by = issued_by[0] 
        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon',
        'Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust',
        'Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign']        
        #finding age of certificate
        startingdate = str(certificate['notBefore'])
        endingdate = str(certificate['notAfter'])
        startingyear = int(startingdate.split()[3])
        endingyear = int(endingDate.split()[3])
        age_of_certificate = endingyear-startingyear
        
        if((usehttps == 1 ) and (issued_by in trusted_Auth) and (age_of_certificate >= 1) ):
            return -1 #legitimate
        elif((usehttps == 1) and (issued_by not in trusted_Auth)):
            return 120 #suspicious
        else:
            return 1 #phishing
        
    except Exception as e:
        return -1

def domain_reg_length(url, subdomain, domain, suffix):
    try:
        #subdomain, domain, suffix = extract(url)
        host = domain + "." + suffix
        #print(host)
        w = whois.whois(host)
        updated = w.updated_date
        exp = w.expiration_date
        length = (exp-updated).days
        #print(length)
        if(length<=365):
            return 1
        else:
            return -1
    except:
        return 0

def fav_icon(url, soup):
    #response = requests.get(url)
    #soup = BeautifulSoup(response.content, 'html.parser')
    hostname = url
    h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
    z = int(len(h))
    if z != 0:
        y = h[0][1]
        hostname = hostname[y:]
        h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
        z = int(len(h))
        if z != 0 :
            hostname = hostname[:h[0][0]]
    for head in soup.find_all('head'):
        for link in soup.find_all('link', href=True):
            dots = [x.start(0) for x in re.finditer('\.', link['href'])]
            if url in head.link['href'] or len(dots) == 1 or hostname in link['href']:
                return -1
            else:
                return 1
    return -1

def port(url, subdomain, domain, suffix):
    try:
        #subdomain, domain, suffix = extract(url)
        host = domain + "." + suffix
        #print (host)
        remote = socket.gethostbyname(host)
        res=[[]]
        ports = [21, 22, 23, 80, 443, 445, 1433, 1521, 3306, 3389]
        for p in ports:
            #print (p)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remote, p))
            #print (result)
            if p!= 80 or p!= 443:
                res = [[result]]
        for r in res:
            if r != 0:
                return 1
        return -1
    except:
        return -1
    
def https_token(url, subdomain, domain, suffix):
    #subdomain, domain, suffix = extract(url)
    host = subdomain + '.' + domain + '.' + suffix
    #print (host)
    if(host.count('https')):
        return 1
    else:
        return -1

def request_url(url, soup, subdomain, domain, suffix):
    #response = requests.get(url)
    #soup = BeautifulSoup(response.content, 'html.parser')
    #subdomain, domain, suffix = extract(url)
    webdomain = domain

    img = soup.find_all('img', src = True)
    total = len(img)
    linked_to_same = 0
    avg = 0
    for image in img:
        subdomain, domain, suffix = extract(image['src'])
        imgdomain = domain
        if(webdomain == imgdomain or imgdomain == ''):
            linked_to_same = linked_to_same + 1

    video = soup.find_all('video', src = True)
    total = total + len(video)
    for vid in video:
        subdomain, domain, suffix = extract(video['src'])
        vid_domain = domain
        if(webdomain == vid_domain or vid_domain == ''):
            linked_to_same = linked_to_same + 1

    audio = soup.find_all('audio', src = True)
    total = total + len(audio)
    for aud in audio:
        subdomain, domain, suffix = extract(audio['src'])
        aud_domain = domain
        if(aud_domain == webdomain or aud_domain == ''):
            linked_to_same = linked_to_same + 1

    embed = soup.find_all('embed', src = True)
    total = total + len(embed)
    for emb in embed:
        subdomain, domain, suffix = extract(embed['src'])
        embed_domain = domain
        if(webdomain == embed_domain or embed_domain == ''):
            linked_to_same = linked_to_same + 1

    i_frame = soup.find_all('i_frame', src = True)
    total = total + len(i_frame)
    for i in i_frame:
        subdomain, domain, suffix = extract(i_frame['src'])
        i_domain = domain
        if(i_domain == webdomain or i_domain == ''):
            linked_to_same = linked_to_same + 1

    linked_out = total - linked_to_same
    if(total != 0):
        avg = linked_out/total
    if(avg < 0.22):
        return -1
    elif(0.22 <= avg <= 0.61):
        return 0
    else:
        return 1

def anchor(url, soup, subdomain, domain, suffix):
    #subdomain, domain, suffix = extract(url)
    webdomain = domain
    #response = requests.get(url)
    #soup = BeautifulSoup(response.content, 'html.parser')
    linked_to_same = 0
    avg = 0
    anch = soup.find_all('a', src=True)
    total = len(anch)
    for a in anch:
        subdomain, domain, suffix = extract(a['src'])
        if(webdomain == domain or domain == ''):
            linked_to_same = linked_to_same + 1
    linked_out = total - linked_to_same
    if(total != 0):
        avg = linked_out/total
    if(avg < 0.31):
        return -1
    elif(0.31 <= avg <= 0.67):
        return 0
    else:
        return 1

def links_in_tags(url, soup, subdomain, domain, suffix):
    #subdomain, domain, suffix = extract(url)
    webdomain = domain
    #response = requests.get(url)
    #soup = BeautifulSoup(response.content, 'html.parser')
    linked_to_same = 0
    avg =0
    meta = soup.find_all('meta', src = True)
    total = len(meta)
    for m in meta:
        subdomain, domain, suffix = extract(meta['src'])
        if(webdomain == domain or domain == ''):
            linked_to_same = linked_to_same + 1

    script = soup.find_all('script', src = True)
    total = total + len(script)
    for s in script:
        subdomain, domain, suffix = extract(s['src'])
        if(webdomain == domain or domain == ''):
            linked_to_same = linked_to_same + 1

    link = soup.find_all('link', src = True)
    total = total + len(link)
    for l in link:
        subdomain, domain, suffix = extract(url)
        if(domain == webdomain or domain == ''):
            linked_to_same = linked_to_same + 1

    linked_out = total - linked_to_same
    if(total != 0):
        avg = linked_out/total
    if(avg< 0.17):
        return -1
    elif(0.17 <= avg <=0.81):
        return 0
    else:
        return 1

def sfh(url, soup):
    try:
        #response = requests.get(url)
        #soup = BeautifulSoup(response.content, 'html.parser')
        form = soup.find_all('form', action = True)
        hostname = url
        h = [(x.start(0), x.end(0)) for x in re.finditer('https://|http://|www.|https://www.|http://www.', hostname)]
        z = int(len(h))
        if z != 0:
            y = h[0][1]
            hostname = hostname[y:]
            h = [(x.start(0), x.end(0)) for x in re.finditer('/', hostname)]
            z = int(len(h))
            if z != 0 :
                hostname = hostname[:h[0][0]]
        for f in form:
            if(f['action'] == "" or f['action'] == "about:blank"):
                return 1
            elif(url not in f['action'] and hostname not in f['action']):
                return 0
            else:
                return -1
    except:
        return 0
    return -1

def submit_to_mail(url, soup):
    try:
        #response = requests.get(url)
        #soup = BeautifulSoup(response.content, 'html.parser')
        if (soup.find('mailto:')):
            return 1
        else:
            return -1
    except:
        return 0
    return 0

def abnormal_url(url, subdomain, domain, suffix):
    #subdomain, domain, suffix = extract(url)
    host = domain + "." + suffix
    match = re.search(host, url)
    if match:
        return -1
    else:
        return 1

def redirects(url):
    response = requests.head(url, allow_redirects = True)
    #print (response.history)
    count = len(response.history)
    #print (total)
    if count <= 1:
        return -1
    elif 1 <= 4:
        return 0
    else:
        return 1

def onmouseover(url, soup):
    #response = requests.get(url)
    #soup = BeautifulSoup(response.content, 'html.parser')
    anch = soup.find_all('a', onmouseover=True)
    for a in anch:
        if(a['onmouseover'] == "window.status"):
            return -1
        else:
            return 1
    return -1

def disable_right_click(url, soup):
    #response = requests.get(url)
    #soup = BeautifulSoup(response.content, 'html.parser')
    script = soup.find_all('script', event=True)
    for s in script:
        if len(s['event.button']):
            return 1
        else:
            return -1
    return -1

def pop_up(url, soup):
    #response = requests.get(url)
    #soup = BeautifulSoup(response.content, 'html.parser')
    popup= soup.find('prompt')
    if popup:
        return 1
    else:
        return -1

def iframe(url, soup):
    try:
        #response = requests.get(url)
        #soup = BeautifulSoup(response.content, 'html.parser')
        i_frame = soup.find_all('i_frame', width = True, height = True, frameBorder = True)
        for i in i_frame:
            if(i['width'] == "0" and i['height'] == "0" and i['frameBorder'] == "0"):
                return 1
            else:
                return -1
        return -1   
    except:
        return -1

def age_of_domain(url, subdomain, domain, suffix):
    try:
        #subdomain, domain, suffix = extract(url)
        host = domain + "." + suffix
        #print(host)
        w = whois.whois(host)
        cd = w.creation_date
        ed = w.expiration_date
        age = (ed-cd).days
        #print (age)
        if age < 180:
            return 1
        else:
            return -1
    except:
        return -1

def dns_record(url, subdomain, domain, suffix):
    try:
        #subdomain, domain, suffix = extract(url)
        host = domain + "." + suffix
        details = socket.gethostbyname(host)
        #print(details)
        if details:
            return -1
        else:
            return 1
    except:
        return 0

def web_traffic(url):
    try:
        rank = bs4.BeautifulSoup(requests.get("http://data.alexa.com/data?cli=10&dat=s&url=" + url)).find("REACH")['RANK']
        rank = int(rank)
        if rank < 100000:
            return -1
        else:
            return 0
    except:
        return -1

def google_index(url):
    site = search(url, 5)
    if site:
        return -1
    else:
        return 1

def statistical_report(url, subdomain, domain, suffix):
    try:
        #subdomain, domain, suffix = extract(url)
        hostname = domain + "." + suffix
        url_match = re.search(
            'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
        ip_address = socket.gethostbyname(hostname)
        ip_match = re.search(
            '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
            '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
            '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
            '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
            '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
            '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
            ip_address)
        if url_match:
            return 1
        elif ip_match:
            return 1
        else:
            return -1
    except:
        return -1

def main(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.content, 'html.parser')
    subdomain, domain, suffix = extract(url)
    check = [[using_ip(url), long_url(url), shortening_services(url), having_at(url), redirecting_double_slash(url), 
    prefix_suffix(url, subdomain, domain, suffix), dots_in_domain(url, subdomain, domain, suffix), 
    https(url, subdomain, domain, suffix), domain_reg_length(url, subdomain, domain, suffix),
    fav_icon(url, soup), port(url, subdomain, domain, suffix), https_token(url, subdomain, domain, suffix), 
    request_url(url, soup, subdomain, domain, suffix), anchor(url, soup, subdomain, domain, suffix), 
    links_in_tags(url, soup, subdomain, domain, suffix), sfh(url, soup), submit_to_mail(url, soup), 
    abnormal_url(url, subdomain, domain, suffix), redirects(url), onmouseover(url, soup), disable_right_click(url, soup),
    pop_up(url, soup), iframe(url, soup), age_of_domain(url, subdomain, domain, suffix), dns_record(url, subdomain, domain, suffix),
    web_traffic(url), google_index(url), statistical_report(url, subdomain, domain, suffix)]]
    print(check)
    return check

