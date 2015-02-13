# -*- coding: utf-8 -*-
from marionette import Marionette, wait, errors
import base64, json, re, os, subprocess, time, urlparse, argparse
import pdb
import requests

# These variables can be overridden by command line arguments - see below
dirname = '/home/hallvord/tmp/'
filename = dirname + 'todo.csv'
def_img_file = dirname + 'screenshot.png'
ignore_file = '/home/hallvord/mozilla/extensions/sitecomptester/ignored_bugs.txt'
start_at = 0
run_until = None
start_url = None
# if this is enabled, we always turn off general.useragent.site_specific_overrides
disable_ua_overrides_by_default = True

# These selectors are meant to enable integration with various bug trackers.
# However, not all of them are used yet, and we probably need more. For example, we probably need
# to define elements to wait for to figure out if a page is "loaded" - especially for webcompat.com because it's
# a client-side JS beast.
# Generally, support for Bugzilla is most advanced at this point.
selector_map = {
	"bugzilla":{
		"bug_links": "td.bz_id_column a",
		"comment_field":"",
		"submit_button": "",
		"url_ref":"#bz_url_edit_container a"
	},
	"webcompat":{
		"bug_links": "p.IssueItem-header a",
		"comment_field":"",
		"submit_button": "",
		"url_ref": "div.Issue-details a"
	},
	"github":{
		"bug_links": "div.issue-title a.issue-title-link",
		"comment_field":"",
		"submit_button": "",
		"url_ref": ".js-comment-body a"
	}
}

def_ua = 'Mozilla/5.0 (Mobile; rv:36.0) Gecko/36.0 Firefox/36.0'

parser = argparse.ArgumentParser(description=("Test a list of sites, find contact points"))
parser.add_argument("-f", dest='datafile', type=str, help="a file of bug data (tab separated 'ID    desc    URL' format)", default=None)
parser.add_argument("-u", dest='listurl', type=str, help="The URL of a bug search of bugs we want to dig into (supports Bugzilla, webcompat.com and GitHub)", default=None)
parser.add_argument("-i", dest='index', type=int, help="the index in the list of the site you want to test, 0-based", default=None)
parser.add_argument("-s", dest='start_at', type=int, help="start at a certain index in list, 0-based", default=0)
parser.add_argument("-n", dest='num', type=int, help="how many entries to run through, 0-based", default=0)
args = parser.parse_args()
if args.index:
    start_at = args.index
    run_until = args.index
if args.start_at is not 0:
    start_at = args.start_at
if args.num is not 0:
    run_until = start_at + args.num
if args.datafile:
	filename = args.datafile
	dirname = os.path.dirname(filename) + os.sep
	def_img_file = dirname + 'screenshot.png'
if args.listurl:
	start_url = args.listurl

def extract_buglist(marionette_instance):
	# bugzilla searches have  'td.bz_id_column a' . GitHub 'div.issue-title a.issue-title-link', webcompat.com 'p.IssueItem-header a'
	bugs = []
	tracker = bugtracker(marionette_instance)
	selector = selector_map[tracker]['bug_links']
	wait_until_ready(marionette_instance, selector)
	try:
		list = marionette_instance.find_elements('css selector', selector)
		for item in list:
			bugs.append([item.get_attribute('href'), item.text])
	except Exception as e:
		print 'Warning: exception when looking for %s' % selector
		print e
	return bugs

def wait_until_ready(marionette_instance, selector):
	wait_for_elm = wait.Wait(marionette_instance, timeout=270, interval=2, ignored_exceptions=errors.NoSuchElementException)
	print('waiting for %s' % selector)
	wait_for_elm.until(lambda marionette_instance: marionette_instance.find_element('css selector', selector))

def bugtracker(marionette_instance):
	url = marionette_instance.get_url()
	if 'bugzilla.mozilla.org' in url:
		return 'bugzilla'
	elif 'webcompat.com' in url:
		return 'webcompat'
	elif 'github.com' in url:
		return 'github'

def get_url_from_bugpage(marionette_instance):
	# Order of selectors: Bugzilla, GitHub, webcompat.com
	url = None
	selector = selector_map[bugtracker(marionette_instance)]["url_ref"]
	wait_until_ready(marionette_instance, selector)
	try:
		item = marionette_instance.find_element('css selector', selector)
		url = item.get_attribute('href')
	except Exception, e:
		print 'Warning: exception when looking for %s' % selector
		print e
	return url

def extract_buglist_from_file(filename):
	bugs = []
	with open(filename, 'r') as handle:
		for url in handle:
			parts = url.split("\t")
			bugs.append(parts)
	return bugs

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

def spoof_firefox_os(m):
    set_mozilla_pref(m, 'general.useragent.override', 'Mozilla/5.0 (Mobile; rv:26.0) Gecko/26.0 Firefox/26.0')
    set_mozilla_pref(m, 'general.useragent.appName', 'Netscape')
    set_mozilla_pref(m, 'general.useragent.vendor', 'Mozilla')
    set_mozilla_pref(m, 'general.useragent.platform', '')
    set_mozilla_pref(m, 'general.useragent.site_specific_overrides', False)

def reset_spoof(m):
    set_mozilla_pref(m, 'general.useragent.override', def_ua)
    set_mozilla_pref(m, 'general.useragent.appName', 'Netscape')
    set_mozilla_pref(m, 'general.useragent.vendor', '')
    set_mozilla_pref(m, 'general.useragent.platform', '')
    if not disable_ua_overrides_by_default:
        set_mozilla_pref(m, 'general.useragent.site_specific_overrides', True)

def spoof_safari_ios(m):
    set_mozilla_pref(m, 'general.useragent.override', 'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/546.10 (KHTML, like Gecko) Version/6.0 Mobile/7E18WD Safari/8536.25')
    set_mozilla_pref(m, 'general.useragent.appName', 'Netscape')
    set_mozilla_pref(m, 'general.useragent.appVersion', '5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/546.10 (KHTML, like Gecko) Version/6.0 Mobile/7E18WD Safari/8536.25')
    set_mozilla_pref(m, 'general.useragent.vendor', 'Apple Computer, Inc.')
    set_mozilla_pref(m, 'general.useragent.platform', 'iPhone')
    set_mozilla_pref(m, 'general.useragent.site_specific_overrides', False)

def spoof_android_browser(m):
    set_mozilla_pref(m, 'general.useragent.override', 'Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; HTC_ONE_X Build/JRO03C) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30')
    set_mozilla_pref(m, 'general.useragent.appName', 'Netscape')
    set_mozilla_pref(m, 'general.useragent.appVersion', '5.0 (Linux; U; Android 4.1.1; en-us; HTC_ONE_X Build/JRO03C) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30')
    set_mozilla_pref(m, 'general.useragent.vendor', 'Google Inc.')
    set_mozilla_pref(m, 'general.useragent.platform', 'Linux armv71')
    set_mozilla_pref(m, 'general.useragent.site_specific_overrides', False)

def set_proxy_server(marionette_instance, ip, port):
	if ip:
		set_mozilla_pref(marionette_instance, 'network.proxy.http', ip)
		set_mozilla_pref(marionette_instance, 'network.proxy.http_port', port)
		set_mozilla_pref(marionette_instance, 'network.proxy.ssl', ip)
		set_mozilla_pref(marionette_instance, 'network.proxy.ssl_port', port)
		set_mozilla_pref(marionette_instance, 'network.proxy.type', 1)
	else:
		set_mozilla_pref(marionette_instance, 'network.proxy.http', '')
		set_mozilla_pref(marionette_instance, 'network.proxy.http_port', 0)
		set_mozilla_pref(marionette_instance, 'network.proxy.ssl', '')
		set_mozilla_pref(marionette_instance, 'network.proxy.ssl_port', 0)
		set_mozilla_pref(marionette_instance, 'network.proxy.type', 0)

def dual_driving():
	try:
		mm = Marionette(host='localhost', port=2829)
		mm.start_session()
		if disable_ua_overrides_by_default:
			set_mozilla_pref(mm, 'general.useragent.site_specific_overrides', False)
			set_mozilla_pref(mm, 'general.useragent.updates.enabled', False)
			
		md = Marionette(host='localhost', port=2828)
		md.start_session()
		md.set_search_timeout(1000) # especially required for webcompat.com JS-driven loading
		ignored_bugs = []
		buglist = []
		for line in open(ignore_file, 'r'):
			if line[0] == '#':
				continue
			ignored_bugs.append(line.strip())
		if start_url:
			print 'Starting from bug search %s' % start_url
			md.navigate(start_url)
			buglist = extract_buglist(md)
		else:
			buglist = extract_buglist_from_file(filename)
		i = 1
		#print(len(buglist))
		for item in buglist:
			if len(item) <= 1:
				print 'Warning: we expect data format ID    Summary    URL, something is missing'
				continue
			if i<start_at:
				i+=1
				continue
			if '://' not in item[0]: # assuming this is Bugzilla data from a tab-separated file - in other words a plain bug number
				md.navigate('https://bugzilla.mozilla.org/show_bug.cgi?id=%s' % item[0])
			else: # we've got a bug tracker URL (right?)
				md.navigate(item[0])

			if len(item) == 2: # URL is not in the data - let's load the bug first and try to get it from there
				url = get_url_from_bugpage(md)
			else:
				url = item[2]
			if not url:
				i+=1
				continue
			if url.strip() == '':
				i+=1
				continue
			if '://' not in url:
			    url = 'http://%s' % url
			url = url.strip().rstrip('\r\n')
			location = urlparse.urlparse(url)
			hostname = location.hostname.rstrip('\r\n')
			print str(i) + ' : ' + url
			reset_spoof(mm)
			try:
				mm.navigate(url)
				print 'READY to analyze %s, \n%s' % (item[0], item[1])
			except:
				print('could not load %s, try again by pressing u\n\n' % url)
			options_menu(mm, url, md)
		mm.delete_session()
		md.delete_session()
	except Exception as err:
		print err
		try:
			mm.delete_session()
		except:
			pass
		try:
			md.delete_session()
		except:
			pass

def options_menu(test_marionette_instance, url, marionette_desktop):
	choice = raw_input("""
Interact with the website if required,
  * press SS, SA or SF to change UA to Safari, Android and Fx OS respectively
  * press R to reload, U for initial URL, S for screenshot,
  * SU [description] to add screenshot to bug,
  * FC to look for contact points, HC to check headers,
  * JS code(); to run JS and see output,
  * RW [comment] to resolve WORKSFORME, RI [comment] for INVALID, RF [comment] for fixed
  * PROXY ip:port to set a proxy - PROXY without arguments to remove
  * press I [reason] to ignore bug for testing, C [comment] to comment and continue
  C to continue -> """)
	extra_text = ''
	bug_id = re.findall(r'\d+', marionette_desktop.get_url())
	if bug_id:
		bug_id = bug_id[0]
	if ' ' in choice: # this supports entering comments directly after the argument
		extra_text = choice[choice.index(' ')+1:]
		choice = choice[:choice.index(' ')]
	choice = choice.lower()
	if choice =='ss':
		spoof_safari_ios(test_marionette_instance)
		test_marionette_instance.delete_all_cookies()
		test_marionette_instance.execute_script('location.reload(true)')
	elif choice =='sa':
		spoof_android_browser(test_marionette_instance)
		test_marionette_instance.delete_all_cookies()
		test_marionette_instance.execute_script('location.reload(true)')
	elif choice =='sf':
		spoof_firefox_os(test_marionette_instance)
		test_marionette_instance.delete_all_cookies()
		test_marionette_instance.execute_script('location.reload(true)')
	elif choice == 'i':
		print 'ignoring %s' % str(items[0])
		ignore_f = open( ignore_file, 'a')
		if extra_text:
			ignore_f.write('# %s\n' % extra_text)
		else:
			ignore_f.write('# ignore decision during dualdriver testing\n')
		ignore_f.write('%s\n' % str(items[0]))
		ignored_bugs.append(items[0])
		ignore_f.close()
	elif choice == 'r':
		test_marionette_instance.execute_script('location.reload(true)')
	elif choice == 'b':
		test_marionette_instance.execute_script('history.back()')
	elif choice == 'u':
		try:
			test_marionette_instance.navigate(url)
		except:
			print('\nerror loading %s, guess you need to move on to next bug..\n' % url)
	elif choice == 's' or choice == 'su':
		# I want a screenshot of the viewport. For this purpose, I consider that better than getting the full page
		# However, WebDriver spec says implementations *should* do the full page thing, and AFAIK there's no convenient way
		# to opt-in to only take the viewport..
		overlay_elm = None
		try:
			test_marionette_instance.execute_script('(function(){var elm=document.createElement(\'overlay\');elm.setAttribute(\'style\', \'display:block; position:fixed;top:0;left:0;right:0;bottom:0\');document.body.appendChild(elm)})()')
			overlay_elm = test_marionette_instance.find_elements('tag name', 'overlay')
		except:
			pass
		if overlay_elm:
			overlay_elm = overlay_elm[0]
			img_data = base64.b64decode(test_marionette_instance.screenshot(element=overlay_elm))
		else:
			img_data = base64.b64decode(test_marionette_instance.screenshot())
		f = open(def_img_file, 'wb')
		f.write(img_data)
		f.close()
		print 'Saved as %s' % def_img_file
		if choice == 'su':
			try:
				marionette_desktop.find_element('css selector', 'a[href*="attachment.cgi?bugid=%s&action=enter"]' % bug_id ).click()
				while 'attachment.cgi' not in marionette_desktop.get_url():
					time.sleep(2)
				wait_until_ready(marionette_desktop, 'input#data')
				marionette_desktop.set_context(marionette_desktop.CONTEXT_CHROME)
				marionette_desktop.execute_script('gBrowser.contentDocument.getElementById("data").value = "%s"' % def_img_file)
				marionette_desktop.set_context(marionette_desktop.CONTEXT_CONTENT)
				if extra_text:
					marionette_desktop.execute_script('document.getElementById("description").value = "%s"' % extra_text)
					#insert_comment(marionette_desktop, extra_text)
				else:
					marionette_desktop.execute_script('document.getElementById("description").value = "%s"' % "Screenshot from Flame smartphone")
					#insert_comment(marionette_desktop, "Screenshot from Flame device")
				marionette_desktop.execute_script('document.getElementById("create").click()')
			except:
				print 'Sorry, failed when attempting to upload a screenshot in Bugzilla'
	elif choice == 'rw' or choice == 'ri' or choice == 'rf':
		resolutions = {'rw':'WORKSFORME', 'ri':'INVALID', 'rf': 'FIXED'}
		insert_comment(marionette_desktop, extra_text)
		marionette_desktop.execute_script('document.getElementById("bug_status").value = "RESOLVED"')
		marionette_desktop.execute_script('document.getElementById("resolution").value = "%s"' %  resolutions[choice])
		submit_bug_form(marionette_desktop)
	elif choice == 'js':
		if extra_text:
			try:
				print(test_marionette_instance.execute_script('return ' + extra_text))
			except:
				print('That JS threw exception!')
		else:
			print('wot, you didn\'t type any code??')
	elif choice == 'fc':
		pdb.set_trace()
		check_results = {}
		look_for_contact_links(test_marionette_instance, check_results)
		# Some sites have special pages dedicated to their social media presence, or limit contact info to the "about" page..
		
		for keyword in ['social', 'about', 'company', 'twitter', 'facebook']:
			elm = find_elem(test_marionette_instance, {"selector": "*[href*='%s'" % keyword})
			if elm:
				test_marionette_instance.navigate(elm.get_attribute('href'))
				look_for_contact_links(test_marionette_instance, check_results)
				test_marionette_instance.go_back()
		contact_desc = []
		for key in check_results.keys():
			val = check_results[key]
			if val:
				contact_desc.append("%s: %s" % (key.capitalize(),val['url']))
			if len(contact_desc):
				insert_comment(marionette_desktop, "If we're going to contact them, here are some possible contact points:\n" + ("\n".join(contact_desc)))
	elif choice == 'hc':
		header_check_data = check_url(url)
		if header_check_data:
			header_check_data = "\n".join(header_check_data)
			insert_comment(marionette_desktop, header_check_data)
	elif choice == 'proxy':
		if extra_text:
			ip_port = extra_text.split(':')
			if len(ip_port) == 2:
				set_proxy_server(test_marionette_instance, ip_port[0], int(ip_port[1]))
			else:
				print('ERROR: wrong arguments to proxy command - try ip:port')
		else:
			set_proxy_server(test_marionette_instance, None, None)
	elif choice == 'c':
		#pdb.set_trace()
		if extra_text:
			insert_comment(marionette_desktop, extra_text)
			submit_bug_form(marionette_desktop)
			try:
				while marionette_desktop.find_element('tag', 'body').text.index('Changes submitted for bug') == -1:
					time.sleep(1)
			except Exception as e:
				print e
				time.sleep(10)
		return # 'continue' means no more menu recursion..

	return options_menu(test_marionette_instance, url, marionette_desktop)

def insert_comment(marionette_instance, text):
	tracker = bugtracker(marionette_instance)
	text = text.replace('"', '\\"')
	text = text.replace("\n", "\\n")
	if tracker == 'bugzilla':
		marionette_instance.execute_script('document.getElementById("comment").value="%s"' % text)
	elif tracker == 'webcompat':
		marionette_instance.execute_script('document.getElementById("Comment-text").value="%s"' % text)
	elif tracker == 'github':
		marionette_instance.execute_script('document.getElementsByName("comment[body]")[0].value="%s"' % text)
	else:
		raise 'don\'t know how to find comment field on this bug tracker ' + url

def submit_bug_form(marionette_instance):
	tracker = bugtracker(marionette_instance)
	if tracker == 'bugzilla':
		marionette_instance.execute_script('document.getElementById("commit").click()')
	elif tracker == 'webcompat':
		marionette_instance.execute_script('document.getElementsByClassName("js-issue-comment-button")[0].click()')
	elif tracker == 'github':
		marionette_instance.execute_script('document.querySelector("button.button.primary").click()')
	else:
		raise 'don\'t know how to find submit button on this bug tracker ' + url


def look_for_contact_links(m, check_results):
    # looking for mailto: links
    elm = find_elem(m, {"selector": "a[href^='mailto:']"})
    if elm:
        check_results["mail"] = elm.get_attribute('href')
        if check_results["mail"]:# remove mailto: prefix
            check_results["mail"] = {"mail": check_results["mail"][7:], "source_page": m.get_url()}

    for text in ['contact', 'feedback', 'kundenservice', 'kontakt', 'kundeservice', 'help', 'webmaster']:
        elm = find_elem(m, {"linktext": text})
        if elm:
            check_results["contactlink"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}
            break
        else:
            breakelm = find_elem(m, {"linktext": text.capitalize()})
            if elm:
                check_results["contactlink"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}
                break
        elm = find_elem(m, {"selector":  "*[href*='%s']" % text})
        if elm:
            check_results["contactlink"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}
            break


    elm = find_elem(m, {"selector": "*[href*='twitter.com/']"})
    if elm:
        check_results["twitter"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}

    elm = find_elem(m, {"selector": "*[href*='facebook.com/']"})
    if elm:
        check_results["facebook"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}

    elm = find_elem(m, {"selector": "*[href*='plus.google']"})
    if elm:
        check_results["google+"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}

    elm = find_elem(m, {"selector": "*[href*='linkedin.']"})
    if elm:
        check_results["linkedin"] = {"url": elm.get_attribute("href"), "source_page": m.get_url()}

    elm = find_elem(m, {"selector": "form[action*='contact']"})
    if "contactform" in check_results and check_results["contactform"] is '' and elm:
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
        elm = find_elem(marionette_instance, {"selector":"frameset"})
        if elm:
            time.sleep(4)
            return
        elm = find_elem(marionette_instance, {"selector":"body"})
        if elm and elm.is_displayed():
            return
        else:
            print 'sleeping because body is not shown yet  (' + str(x) + '/10)'
            time.sleep(5)




def find_elem(marionette_instance, targets):
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

UAS = {
    "b2g": "Mozilla/5.0 (Mobile; rv:29.0) Gecko/29.0 Firefox/29.0",
    "ios": "Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25",
    "fxa": "Mozilla/5.0 (Android; Mobile; rv:26.0) Gecko/26.0 Firefox/26.0"
}


def make_request(url, ua):
    session = requests.Session()
    session.headers.update({'User-Agent': ua})
    session.headers.update({'Cookies': None})
    session.headers.update({'Cache-Control': 'no-cache, must-revalidate'})
    print 'Will now request %s with UA %s'%(url, ua)
    r = session.get(url, allow_redirects=False, verify=False)
    return r


def dump(response, output):
    wanted_headers = ['content-length', 'location', 'content-type']
    output.append("Response for: '{}'\n".format(response.request.headers['user-agent']))
    output.append("Response Status: {}\n".format(response.status_code))
    for key, value in response.headers.iteritems():
        if key in wanted_headers:
            output.append("{}: {}\n".format(key, value))
    output.append("\n")

def check_url(url, iteration=0, orig_url = ''):
    responses = []
    if re.search('^/', url) and orig_url != '': # We're redirected to a relative URL..
        url = urljoin(orig_url, url)
    for ua in UAS.itervalues():
        response = make_request(url, ua)
        responses.append(response)
        # dump(response)
    # Now compare selected responses..
    output = []
    try:
        if not 'content-length' in responses[0].headers:
            responses[0].headers['content-length'] = 0
        if not 'content-length' in responses[1].headers:
            responses[1].headers['content-length'] = 0
        if not 'content-length' in responses[2].headers:
            responses[2].headers['content-length'] = 0
        biggest_cl = max(int(responses[0].headers['content-length']), int(responses[1].headers['content-length']), int(responses[2].headers['content-length']))
        smallest_cl = min(int(responses[0].headers['content-length']), int(responses[1].headers['content-length']), int(responses[2].headers['content-length']))
        difference = abs(biggest_cl - smallest_cl)
        if biggest_cl > 0:
            if int(float(difference) / float(biggest_cl)*100 ) > 10:
                output.append('Significant difference in source code:\nSmallest response has Content-Length: '+str(smallest_cl))
                output.append('\nLargest response has Content-Length: '+str(biggest_cl)+'\n')
    except Exception,e:
        print 'Exception 1'
        print e
        pass
    try:
        if 'location' in responses[0].headers and not 'location' in responses[1].headers:
            output.append('\nFirefox OS is redirected to '+responses[0].headers['location']+', Firefox for Android not redirected\n')
        elif 'location' in responses[1].headers and not 'location' in responses[0].headers:
            output.append('\nFirefox Android is redirected to %s, Firefox OS not redirected' % str(responses[1].headers['location']))
        elif 'location' in responses[1].headers and 'location' in responses[0].headers:
            if responses[1].headers['location'] != responses[0].headers['location']:
                output.append('\nFirefox OS is redirected to '+responses[0].headers['location']+', Firefox for Android is redirected to '+responses[1].headers['location'])
            elif responses[1].headers['location'] == responses[0].headers['location']:
                if iteration == 0: # follow redirects only once
                    return check_url(responses[1].headers['location'], iteration+1, url)

        if 'location' in responses[0].headers and not 'location' in responses[2].headers:
            output.append('\nFirefox OS is redirected to '+responses[0].headers['location']+', Safari on iPhone not redirected\n')
        elif 'location' in responses[2].headers and not 'location' in responses[0].headers:
            output.append('\nSafari on iPhone is redirected to %s, Firefox OS not redirected' % str(responses[2].headers['location']))
        elif 'location' in responses[2].headers and 'location' in responses[0].headers:
            if responses[2].headers['location'] != responses[0].headers['location']:
                output.append('\nFirefox OS is redirected to '+responses[0].headers['location']+', Safari on iPhone is redirected to '+responses[2].headers['location'])
            elif responses[2].headers['location'] == responses[0].headers['location']:
                if iteration < 2: # follow redirects only once
                    return check_url(responses[2].headers['location'], iteration+1, url)

        if len(output)>0:
            output.append('\n\nSelected HTTP response headers (Firefox OS, Firefox on Android, Safari on iPhone):\n\n')
            dump(responses[0], output)
            dump(responses[1], output)
            dump(responses[2], output)
    except Exception,e:
        print 'Exception 2'
        print e
        return []

    return output



if __name__ == '__main__':
	dual_driving()
