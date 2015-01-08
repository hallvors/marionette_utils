# -*- coding: utf-8 -*-
from marionette import Marionette, wait, errors
import base64, json, re, os, subprocess, time, urlparse, argparse
import pdb

# These variables can be overridden by command line arguments - see below
dirname = '/home/hallvord/tmp/'
filename = dirname + 'todo.csv'
def_img_file = dirname + 'screenshot.png'
ignore_file = '/home/hallvord/mozilla/extensions/sitecomptester/ignored_bugs.txt'
start_at = 0
run_until = None
start_url = None

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
	for selector in ['td.bz_id_column a', 'div.issue-title a.issue-title-link', 'p.IssueItem-header a']:
		try:
			list = marionette_instance.find_elements('css selector', selector)
			for item in list:
				bugs.append([item.get_attribute('href'), item.text])
			if len(list) > 0:
				break
		except Exception as e:
			print 'Warning: exception when looking for %s' % selector
			print e
	return bugs

def get_url_from_bugpage(marionette_instance):
	# Order of selectors: Bugzilla, GitHub, webcompat.com
	url = None
	for selector in ['#bz_url_edit_container a', '.js-comment-body a', 'div.Issue-details a']:
		try:
			item = marionette_instance.find_element('css selector', selector)
			url = item.get_attribute('href')
			break
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

def reset_spoof(m):
    set_mozilla_pref(m, 'general.useragent.override', '')
    set_mozilla_pref(m, 'general.useragent.appName', '')
    set_mozilla_pref(m, 'general.useragent.vendor', '')
    set_mozilla_pref(m, 'general.useragent.platform', '')

def spoof_safari_ios(m):
    set_mozilla_pref(m, 'general.useragent.override', 'Mozilla/5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/546.10 (KHTML, like Gecko) Version/6.0 Mobile/7E18WD Safari/8536.25')
    set_mozilla_pref(m, 'general.useragent.appName', 'Netscape')
    set_mozilla_pref(m, 'general.useragent.appVersion', '5.0 (iPhone; CPU iPhone OS 7_0 like Mac OS X) AppleWebKit/546.10 (KHTML, like Gecko) Version/6.0 Mobile/7E18WD Safari/8536.25')
    set_mozilla_pref(m, 'general.useragent.vendor', 'Apple Computer, Inc.')
    set_mozilla_pref(m, 'general.useragent.platform', 'iPhone')

def spoof_android_browser(m):
    set_mozilla_pref(m, 'general.useragent.override', 'Mozilla/5.0 (Linux; U; Android 4.1.1; en-us; HTC_ONE_X Build/JRO03C) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30')
    set_mozilla_pref(m, 'general.useragent.appName', 'Netscape')
    set_mozilla_pref(m, 'general.useragent.appVersion', '5.0 (Linux; U; Android 4.1.1; en-us; HTC_ONE_X Build/JRO03C) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30')
    set_mozilla_pref(m, 'general.useragent.vendor', 'Google Inc.')
    set_mozilla_pref(m, 'general.useragent.platform', 'Linux armv71')



def dual_driving():
	try:
		mm = Marionette(host='localhost', port=2829)
		mm.start_session()
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
  * JS code(); to run JS and see output,
  * RW [comment] to resolve WORKSFORME, RI [comment] for INVALID
  * press I [reason] to ignore bug for testing, C [comment] to comment and continue
  C to continue -> """)
	extra_text = ''
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
		img_data = base64.b64decode(test_marionette_instance.screenshot())
		f = open(def_img_file, 'wb')
		f.write(img_data)
		f.close()
		print 'Saved as %s' % def_img_file
		if choice == 'su':
			try:
				marionette_desktop.find_element('css selector', 'a[href*="attachment.cgi?bugid="]').click()
				while 'attachment.cgi' not in marionette_desktop.get_url():
					time.sleep(1)
				marionette_desktop.set_context(marionette_desktop.CONTEXT_CHROME)
				marionette_desktop.execute_script('gBrowser.contentDocument.getElementById("data").value = "%s"' % def_img_file)
				marionette_desktop.set_context(marionette_desktop.CONTEXT_CONTENT)
				if extra_text:
					insert_comment(marionette_desktop, extra_text)
				else:
					insert_comment(marionette_desktop, "Screenshot from Flame device")
				marionette_desktop.execute_script('document.getElementById("create").click()')
			except:
				print 'Sorry, failed when attempting to upload a screenshot in Bugzilla'
	elif choice == 'rw' or choice == 'ri':
		resolutions = {'rw':'WORKSFORME', 'ri':'INVALID'}
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
	elif choice == 'c':
		pdb.set_trace()
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
	url = marionette_instance.get_url()
	if 'bugzilla.mozilla' in url:
		marionette_instance.execute_script('document.getElementById("comment").value="%s"' % text)
	elif 'webcompat.com' in url:
		marionette_instance.execute_script('document.getElementById("Comment-text").value="%s"' % text)
	elif 'github.com' in url:
		marionette_instance.execute_script('document.getElementsByName("comment[body]")[0].value="%s"' % text)
	else:
		raise 'don\'t know how to find comment field on this bug tracker ' + url

def submit_bug_form(marionette_instance):
	url = marionette_instance.get_url()
	if 'bugzilla.mozilla' in url:
		marionette_instance.execute_script('document.getElementById("commit").click()')
	elif 'webcompat.com' in url:
		marionette_instance.execute_script('document.getElementsByClassName("js-issue-comment-button")[0].click()')
	elif 'github.com' in url:
		marionette_instance.execute_script('document.querySelector("button.button.primary").click()')
	else:
		raise 'don\'t know how to find submit button on this bug tracker ' + url

if __name__ == '__main__':
	dual_driving()
