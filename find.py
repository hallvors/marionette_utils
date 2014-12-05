# TODO: don't put this on GitHub or similar unless the Similarweb API key is first
# moved into a suitable config file..

from marionette import Marionette
import base64, json, re, os, subprocess, time, urlparse, tldextract, difflib, argparse, glob, urllib2, datetime
import pdb
from pprint import pprint



dirname = 'C:\\mozilla\\poodle\\'
filename = dirname + 'alexa-ssl3.csv'
start_at = 0
run_until = None

parser = argparse.ArgumentParser(description=("Test a list of sites, find contact points"))
parser.add_argument("-i", dest='index', type=int, help="the index in the list of the site you want to test, 0-based", default=None)
parser.add_argument("-s", dest='start_at', type=int, help="start at a certain index in list, 0-based", default=0)
parser.add_argument("-n", dest='num', type=int, help="how many entries to run through, 0-based", default=0)
args = parser.parse_args()
if args.index is not None:
    start_at = args.index
    run_until = args.index
if args.start_at is not 0:
    start_at = args.start_at
if args.num is not 0:
    run_until = start_at + args.num

m = Marionette(host='localhost', port=2828)
m.start_session()
m.set_search_timeout(1000)
all_results = {}

def get_remote_file(url, req_json=False):
    pprint('Getting '+url)
    req = urllib2.Request(url)
    if req_json:
        req.add_header('Accept', 'application/json')
#   req.add_header('User-agent', 'Mozilla/5.0 (Windows NT 5.1; rv:27.0) Gecko/20100101 Firefox/27.0')
    bzresponse = urllib2.urlopen(req, timeout=240)
    return bzresponse.read()


def read_json_file(path):
    if os.path.exists(path):
        idx_f = open(path)
        try:
            data = json.loads(idx_f.read())
        except Exception, e:
            data = json.loads(idx_f.read())
        idx_f.close()
    else:
        data = {}
    return data

def load_and_check(url, hostname, clear_session=True):
    if url:
        try:
            if clear_session:
                m.delete_all_cookies()
            #m.delete_session()
            #m.start_session()
            print "now loading "+url
            m.navigate(url)
        except:
            try:
                print 'Failed loading '+url+', trying again with www.'
                m.delete_session()
                m.start_session()
                url = re.sub('://', '://www.', url)
                m.navigate(url)
            except:
                print 'Error loading '+url
                return
    time.sleep(2)
    wait_for_readystate_complete(m)
    check_results = {"mail":"", "twitter":"", "contactform":"", "facebook":"", "google+":"", "linkedin":""}
    return_object = {}
    look_for_contact_links(m, check_results)
    # Some sites have special pages dedicated to their social media presence, or limit contact info to the "about" page..
    for keyword in ['social', 'about', 'company', 'twitter', 'facebook']:
        elm = findElm(m, {"selector":"*[href*='%s'" % keyword})
        if elm:
            m.navigate(elm.get_attribute('href'))
            look_for_contact_links(m, check_results)
            m.go_back()

    # Get Category and Rank information from Similarweb
    try:
        categoryrank = json.loads(get_remote_file("http://api.similarweb.com/Site/%s/v2/categoryrank?Format=JSON&UserKey=1e20345e4874ac9d2fb36d82df152a64" % hostname, True))
    except:
        categoryrank = {"Category":"", "CategoryRank":""}
    return_object["categoryrank"] = categoryrank
    # http://www.ipv.sx/poodled/poodlecheck.pl?host=pandawill.com
    try:
        return_object["ssl_status"] = json.loads(get_remote_file("http://www.ipv.sx/poodled/poodlecheck.pl?host=%s" % hostname, True))
    except:
        return_object["ssl_status"] = {"ssl_enabled":-1,"sslv3_enabled":-1,"tls_enabled":-1}
    return_object["ssl_status"]["date_checked"] = str(datetime.date.today())
    return_object['contactpoints'] = check_results
    return return_object


def look_for_contact_links(m, check_results):
    # looking for mailto: links
    elm = findElm(m, {"selector":"a[href^='mailto:']"})
    if elm:
        check_results["mail"] = elm.get_attribute('href')
        if check_results["mail"]:# remove mailto: prefix
            check_results["mail"] = {"mail": check_results["mail"][7:], "source_page": m.get_url()}

    for text in ['contact', 'feedback', 'kundenservice', 'kontakt', 'kundeservice', 'help', 'webmaster']:
        elm = findElm(m, {"linktext":text})
        if elm:
            check_results["contactlink"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}
            break
        else:
            breakelm = findElm(m, {"linktext":text.capitalize()})
            if elm:
                check_results["contactlink"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}
                break
        elm = findElm(m, {"selector": "*[href*='%s']" % text})
        if elm:
            check_results["contactlink"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}
            break


    elm = findElm(m, {"selector":"*[href*='twitter.com/']"})
    if elm:
        check_results["twitter"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}

    elm = findElm(m, {"selector":"*[href*='facebook.com/']"})
    if elm:
        check_results["facebook"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}

    elm = findElm(m, {"selector":"*[href*='plus.google']"})
    if elm:
        check_results["google+"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}

    elm = findElm(m, {"selector":"*[href*='linkedin.']"})
    if elm:
        check_results["linkedin"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}

    elm = findElm(m, {"selector":"form[action*='contact']"})
    if check_results["contactform"] is '' and elm:
        check_results["contactform"] = {"url": m.get_url(), "source_page": m.get_url()}


def wait_for_readystate_complete(marionette_instance):
    for x in xrange(1,10):
        s = marionette_instance.execute_script('return document.readyState')
        if 'complete' not in s:
            print 'sleeping because readyState is now '+s + ' (' + str(x) + '/10)'
            time.sleep(5)
    # readyState is now complete. Let's check if the BODY element is 'displayed'
    for x in xrange(1,10):
        # if we have a FRAMESET element, we should skip this check
        elm = findElm(marionette_instance, {"selector":"frameset"})
        if elm:
            time.sleep(4)
            return
        elm = findElm(marionette_instance, {"selector":"body"})
        if elm and elm.is_displayed():
            return
        else:
            print 'sleeping because body is not shown yet  (' + str(x) + '/10)'
            time.sleep(5)




def findElm(marionette_instance, targets):
    """
    This method takes a list of objects with id and/or name and/or selector properties
    It returns the first matching element
    [{"id":"foo", "name":"bar", "selector":"body nav ol"}]
    """
    if not isinstance(targets, list):
        targets = [targets]
    for target in targets:
        if 'id' in target:
            #print 'id '+ target['id']
            try:
                return marionette_instance.find_element('id', target['id'])
            except:
                pass
        if 'name' in target:
            #print 'name '+target['name']
            try:
                return marionette_instance.find_element('name', target['name'])
            except:
                pass
        if 'selector' in target:
            #print 'selector '+target['selector']
            try:
                return marionette_instance.find_element('css selector', target['selector'])
            except:
                pass
        if 'linktext' in target:
            try:
                return marionette_instance.find_element('partial link text', target['linktext'])
            except:
                pass

def set_mozilla_pref(marionette_instance, name, value):
    marionette_instance.set_context(marionette_instance.CONTEXT_CHROME)
    if type(value) is str:
        js = """
            var pref = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
            var str = Components.classes["@mozilla.org/supports-string;1"].createInstance(Components.interfaces.nsISupportsString);
            str.data = "%s";
            pref.setComplexValue("%s", Components.interfaces.nsISupportsString, str)
        """ % (value, name)
    elif type(value) is bool:
        js = """
            var pref = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
            pref.setBoolPref("%s", %s)
        """ % (name, str(value).lower())
    elif type(value) is int:
        js = """
            var pref = Components.classes["@mozilla.org/preferences-service;1"].getService(Components.interfaces.nsIPrefBranch);
            pref.setIntPref("%s", %s)
        """ % (name, str(value))

    marionette_instance.execute_script(js)
    marionette_instance.set_context(marionette_instance.CONTEXT_CONTENT)


i=0
# If we don't start at 0, we must take care to not overwrite old results..
#if start_at > 0 and os.path.exists(dirname+'results.json'):
if os.path.exists(dirname+'results.json'):
    all_results = read_json_file(dirname+'results.json')
print "will play urls from %s" % filename
print "Will run from %i" % start_at
if run_until > 0:
    print ".. to %i" % run_until

set_mozilla_pref(m, 'dom.disable_beforeunload', True)
with open(filename, 'r') as handle:
    for url in handle:
        if(run_until and i > run_until):
            quit()

        if i<start_at or url.strip() == '':
            i+=1
            continue
        parts = url.split("\t")
        if len(parts) == 2:
            i+=1
            continue # We're loading a tab-separated file with bug \t summary \t url, and there is no URL..
        # Name  #Certs  AlexaName   Rank    Exact   SSL version
        if parts[2] in all_results: # we already know about this host
            print 'Skipping %s, we already know about it' % parts[2]
            if parts[0] not in all_results[parts[2]]["domains"]:
                all_results[parts[2]]["domains"].append(parts[0])
            i+=1
            continue
        elif len(parts) >= 3:
            url = parts[0]
        if '://' not in url:
            url = 'https://%s' % url
        url = url.strip().rstrip('\r\n')
        hostname = parts[2]
        print str(i) + ' : ' + url
        try:
            results = load_and_check(url, hostname)
            if results:
                results["domains"] = [url]
                results["name"] = parts[0]
                results["num_certs"] = parts[1]
                results["hostname"] = parts[2]
                results["alexa_rank"] = parts[3]
                results["ssl_version"] = parts[5]
                print 'results: '
                print results
        except Exception,e:
            print e
            try:
                m.delete_session()
            except:
                pass
            try:
                m.start_session()
            except:
                pass
            i+=1
            continue
        if results:
            all_results[parts[2]] = results
            jsf = open(dirname + 'results.json', 'w')
            jsf.write(json.dumps(all_results, indent=4))
            jsf.close();

        i+=1
