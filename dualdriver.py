# -*- coding: utf-8 -*-
from marionette import Marionette
from marionette_driver import wait, errors
from marionette_driver.errors import NoSuchElementException
import base64, json, re, os, subprocess, shlex, time, urlparse, argparse
import pdb
import requests
import subprocess
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
		"comment_field":"textarea#comment",
		"submit_button": "input#commit",
		"url_ref":"#bz_url_edit_container a"
	},
	"webcompat":{
		"bug_links": "header.wc-IssueList-header a",
		"comment_field":"textarea.wc-Comment-wrapper.js-Comment-text",
		"submit_button": "button.js-Issue-comment-button",
		"submit_close_button": "button.js-Issue-state-button",
		"url_ref": "div.wc-Issue-details a",
		"upload_input": "input#image"
	},
	"github":{
		"bug_links": "div.issue-title a.issue-title-link",
		"comment_field":".js-new-comment-form textarea#new_comment_field",
		"submit_button": ".js-new-comment-form button.btn-primary",
		"submit_close_button":"button[name=\"comment_and_close\"]",
		"url_ref": ".js-comment-body a",
		"upload_input": "input.manual-file-chooser"
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
	#pdb.set_trace()
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

def get_device_map():
	device_data_ar = subprocess.Popen('adb devices -l', shell=True, stdout=subprocess.PIPE).stdout.read().splitlines()
	device_data = {}
	#356cd085               device usb:1-8 product:flame model:flame device:flame
	#SH24SW104069           device usb:1-7 product:htc_europe model:HTC_One_X device:endeavoru
	rx = re.compile('(\S*)\s+device usb:(\S+) product:(\S+) model:(\S+) device:(\S+)')
	for dev_str in device_data_ar:
		m = rx.search(dev_str)
		if m:
			device_data[m.group(1)] = {
				'device usb': m.group(2),
				'product': m.group(3),
				'model': m.group(4),
				'device': m.group(5)
			}
			# Right now the script works with two device (types):
			# Firefox OS "Flame" and "something else"
			device_data[m.group(1)]['isFxOS'] = 'flame' in device_data[m.group(1)]['product']
			device_data[m.group(1)]['isAndroid'] = not device_data[m.group(1)]['isFxOS']
	print('Detected devices: ')
	print(device_data)
	return device_data

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
		print('Will connect to mobile..')
		mm = Marionette(host='localhost', port=2829)
		mm.start_session()
		if disable_ua_overrides_by_default:
			set_mozilla_pref(mm, 'general.useragent.site_specific_overrides', False)
			set_mozilla_pref(mm, 'general.useragent.updates.enabled', False)
			
		print('Will connect to desktop...')
		md = Marionette(host='localhost', port=2828)
		md.start_session()
		md.set_search_timeout(1000) # especially required for webcompat.com JS-driven loading
		ignored_bugs = []
		buglist = []
		device_map = get_device_map()

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
			buglink = ''
			if '://' not in item[0]: # assuming this is Bugzilla data from a tab-separated file - in other words a plain bug number
				# TODO: will we ever process lists of webcompat.com "plain numbers"??
				buglink = 'https://bugzilla.mozilla.org/show_bug.cgi?id=%s' % item[0]
			else: # we've got a bug tracker URL (right?)
				buglink = item[0]
			# users who have bugzilla's "load next bug in search" don't need an extra navigate() call
			if buglink not in md.get_url():
				print('Item %s, Loading bug %s'%(i,item[0]))
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
				try_to_launch_url_in_android(device_map, url)
				print 'READY to analyze %s, \n%s' % (item[0], item[1])
			except:
				print('could not load %s, try again by pressing u\n\n' % url)
			options_menu(mm, url, md, device_map)
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

def options_menu(test_marionette_instance, url, marionette_desktop, device_map):
	choice = raw_input("""
Interact with the website if required,
  * press SS, SA or SF to change UA to Safari, Android and Fx OS respectively
  * press R to reload, U for initial URL, U new_url to load a different URL
  * S for screenshot,
  * SU [description] to add screenshot to bug (magic word "Android" in description),
  * FC to look for contact points, HC to check headers,
  * JS code(); to run JS and see output,
  * L somelabel to apply this label to the issue (whiteboard on Bugzilla, [ ] are added)
  * RW [comment] to resolve WORKSFORME, RI [comment] for INVALID, RF [comment] for fixed
  * PROXY ip:port to set a proxy - PROXY without arguments to remove
  * press I [reason] to ignore bug for testing, C [comment] to comment and continue
  C to continue -> """)
	extra_text = ''
	# sometimes one types initial space by mistake, ignore it
	choice = choice.lstrip()
	bug_id = re.findall(r'\d+', marionette_desktop.get_url())
	tracker = bugtracker(marionette_desktop)
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
		try_to_launch_url_in_android(device_map, 'javascript:location.reload(true)')
	elif choice == 'b':
		test_marionette_instance.execute_script('history.back()')
		try_to_launch_url_in_android(device_map, 'javascript:history.back()')
	elif choice == 'u':
		try:
			if extra_text:
				try_to_launch_url_in_android(device_map, extra_text) # we do this first because the next line might throw
				test_marionette_instance.navigate(url, extra_text)
			else:
				try_to_launch_url_in_android(device_map, url) # we do this first because the next line might throw
				test_marionette_instance.navigate(url)
		except:
			print('\nerror loading %s, guess you need to move on to next bug..\n' % url)
	elif choice == 's' or choice == 'su':
		if 'Android' in extra_text:
			for device in device_map:
				if device_map[device]['isAndroid']:
					subprocess.call(['adb', '-s', device, 'shell', 'screencap', '/sdcard/screenshot.png'])
					subprocess.call(['adb', '-s', device, 'pull', '/sdcard/screenshot.png', def_img_file])
					break
		else:
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
			if not extra_text:
				extra_text = 'Screenshot from device'
			if tracker == 'bugzilla':
				try:
					marionette_desktop.find_element('css selector', 'a[href*="attachment.cgi?bugid=%s&action=enter"]' % bug_id ).click()
					while 'attachment.cgi' not in marionette_desktop.get_url():
						time.sleep(2)
					wait_until_ready(marionette_desktop, 'input#data')
					marionette_desktop.set_context(marionette_desktop.CONTEXT_CHROME)
					marionette_desktop.execute_script('gBrowser.contentDocument.getElementById("data").value = "%s"' % def_img_file)
					marionette_desktop.set_context(marionette_desktop.CONTEXT_CONTENT)
					marionette_desktop.execute_script('document.getElementById("description").value = "%s"' % extra_text)
					marionette_desktop.execute_script('document.getElementById("create").click()')
				except:
					print 'Sorry, failed when attempting to upload a screenshot in Bugzilla'
			elif tracker == 'webcompat' or tracker == 'github':
				marionette_desktop.set_context(marionette_desktop.CONTEXT_CHROME)
				marionette_desktop.execute_script('gBrowser.contentDocument.querySelector("%s").value = "%s"' % (selector_map[tracker]['upload_input'], def_img_file))
				marionette_desktop.set_context(marionette_desktop.CONTEXT_CONTENT)
				comment_field = marionette_desktop.find_element('css selector', selector_map[tracker]['comment_field'])
				attempts = 11
				while marionette_desktop.execute_script('return arguments[0].value', [comment_field]) == '' and attempts > 0:
					attempts = attempts - 1
					time.sleep(1)				
				insert_comment(marionette_desktop, extra_text)
				submit_bug_form(marionette_desktop)
				
	elif choice == 'rw' or choice == 'ri' or choice == 'rf':
		resolutions = {'rw':'WORKSFORME', 'ri':'INVALID', 'rf': 'FIXED'}
		#pdb.set_trace()
		insert_comment(marionette_desktop, extra_text)
		if tracker == 'bugzilla':
			set_label_or_status(marionette_desktop, resolutions[choice])
			submit_bug_form(marionette_desktop)
		else:
			set_label_or_status(marionette_desktop, resolutions[choice].lower())
			submit_bug_form(marionette_desktop, True)

		return # means no more menu recursion, i.e. load next bug..
	elif choice == 'js':
		if extra_text:
			try:
				print(test_marionette_instance.execute_script('return ' + extra_text))
				try_to_launch_url_in_android(device_map, 'javascript:%s' % extra_text)
			except:
				print('That JS threw exception!')
		else:
			print('wot, you didn\'t type any code??')
	elif choice == 'fc':
		check_results = {}
		look_for_contact_links(test_marionette_instance, check_results)
		# Some sites have special pages dedicated to their social media presence, or limit contact info to the "about" page..
		
		for keyword in ['social', 'about', 'company', 'contact', 'twitter', 'facebook']:
			elm = find_elem(test_marionette_instance, {"selector": "*[href*='%s'" % keyword})
			if elm:
				test_marionette_instance.navigate(elm.get_attribute('href'))
				look_for_contact_links(test_marionette_instance, check_results)
				test_marionette_instance.go_back()
		contact_desc = []
		for key in check_results.keys():
			val = check_results[key]
			print(val)
			if val and 'url' in val:
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
	elif choice == 'l':
		if extra_text:
			set_label_or_status(marionette_desktop, extra_text)
	elif choice == 'c':
		#pdb.set_trace()
		if extra_text:
			insert_comment(marionette_desktop, extra_text)
			submit_bug_form(marionette_desktop)
			if tracker == 'bugzilla':
				try:
					while marionette_desktop.find_element('tag name', 'body').text.index('Changes submitted for bug') == -1:
						time.sleep(1)
				except Exception as e:
					print e
					time.sleep(10)
		return # means no more menu recursion..

	return options_menu(test_marionette_instance, url, marionette_desktop, device_map)

def insert_comment(marionette_instance, text):
	print('insert_comment called')
	tracker = bugtracker(marionette_instance)
	elm = marionette_instance.find_element('css selector', selector_map[tracker]['comment_field'])
	if elm:
		marionette_instance.execute_script('arguments[0].value = arguments[0].value.length && arguments[0].value !== arguments[1] ? arguments[0].value +\'\\n \'+ arguments[1] : arguments[1]', [elm, text])
	else:
		raise 'don\'t know how to find comment field on this bug tracker ' + marionette_instance.get_url()

def submit_bug_form(marionette_instance, close_bug=False):
	tracker = bugtracker(marionette_instance)
	try:
		if close_bug and 'submit_close_button' in selector_map[tracker]:
			marionette_instance.execute_script('document.querySelector(arguments[0]).click()', [str(selector_map[tracker]['submit_close_button'])])
			# There's a TODO in webcompat's source - we somehow trigger a code path that doesn't addd the comment..
			if tracker == 'webcompat':
				time.sleep(3)
				marionette_instance.execute_script('document.querySelector(arguments[0]).click()', [str(selector_map[tracker]['submit_button'])])
		else:
			marionette_instance.execute_script('document.querySelector(arguments[0]).click()', [str(selector_map[tracker]['submit_button'])])
		if tracker == 'github' or tracker == 'webcompat':
			time.sleep(5) # TODO: find a better "done" indication
	except Exception as e:
		print 'don\'t know how to find submit button on this bug tracker ' + marionette_instance.get_url()
		raise e

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
        url = url.join(orig_url, url)
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

def set_label_or_status(marionette_instance, labelstr):
	tracker = bugtracker(marionette_instance)
	# Minor issue: labelstr is sometimes uppercased (for Bugzilla status), but we don't use 'labelstr in statuslabels' for this case
	statuslabels = ['needsdiagnosis', 'needscontact', 'needsinfo', 'invalid', 'worksforme', 'duplicate', 'wontfix', 'contactready', 'sitewait', 'fixed']
	if tracker == 'webcompat':
		marionette_instance.find_element('css selector', 'button.js-LabelEditorLauncher').click()
		try:
			marionette_instance.find_element('css selector', 'input.LabelEditor-list-item-checkbox[name="%s"]' % labelstr.lower()).click()
		except NoSuchElementException as e:
			print('No such label: %s' % labelstr)
		marionette_instance.find_element('css selector', 'button.wc-LabelEditor-button').click()
	elif tracker == 'github':
		marionette_instance.find_element('css selector', 'div.label-select-menu>button.discussion-sidebar-heading.discussion-sidebar-toggle.js-menu-target>span.octicon').click()
		wait_until_ready(marionette_instance,  'input[name="issue\\[labels\\]\\[\\]"][value="status-worksforme"]')
		if labelstr in statuslabels:
			for other_status in ['needsdiagnosis', 'needscontact', 'needsinfo']:
				try:
					elm = marionette_instance.find_element('css selector', 'input[name="issue\\[labels\\]\\[\\]"][value="status-%s"]' % other_status)
					if elm and elm.is_selected(): # hack: we've found a display:none checkbox, Marionette won't let us click() it. Find the next element..
						elm = marionette_instance.execute_script('arguments[0].nextElementSibling.scrollIntoView();return arguments[0].nextElementSibling', [elm])
						elm.click()
				except Exception as e:
					print e
		try:
			elm = marionette_instance.find_element('css selector', 'input[name="issue\\[labels\\]\\[\\]"][value="status-%s"]' % labelstr.lower())
		except NoSuchElementException as e:
			print('No such label: %s' % labelstr)
		elm = marionette_instance.execute_script('arguments[0].nextElementSibling.scrollIntoView();return arguments[0].nextElementSibling', [elm])
		elm.click()
		marionette_instance.find_element('css selector', 'div.label-select-menu span.octicon.octicon-x.js-menu-close').click()
	elif tracker == 'bugzilla':
		# whiteboard or real status?
		whiteboardlabels = ['needsdiagnosis', 'needscontact', 'needsinfo','contactready', 'sitewait']
		if labelstr in whiteboardlabels:
			whiteboard = marionette_instance.find_element('css selector', 'input[id="status_whiteboard"]')
			current_value = marionette_instance.execute_script('return arguments[0].value', [whiteboard])
			# mutually exclusive..
			for thislabel in whiteboardlabels:
				if "[%s]" % thislabel in current_value:
					current_value = current_value.replace("[%s]" % thislabel, '')
			current_value = "%s [%s]" % (current_value, labelstr)
			current_value = marionette_instance.execute_script('return arguments[0].value = arguments[1]', [whiteboard, current_value.strip()])
		else:
			marionette_desktop.execute_script('document.getElementById("bug_status").value = "RESOLVED"')
			marionette_desktop.execute_script('document.getElementById("resolution").value = "%s"' %  labelstr)

# Replace this value to push to different release channels.
# Nightly = org.mozilla.fennec
# Aurora = org.mozilla.fennec_aurora
# Beta = org.mozilla.firefox_beta
# Release = org.mozilla.firefox
ANDROID_APP_ID='org.mozilla.fennec'

# adb arguments. Needs the following strings interpolated:
# ID of device (as given by "adb devices"
# URL to open
# ID of target app (see ANDROID_APP_ID above)
ADB_ARGS = 'adb -s %s shell am start -a android.intent.action.VIEW  -c android.intent.category.DEFAULT -d %s  -n %s/.App'


def try_to_launch_url_in_android(device_map, url):
	try:
		for device in device_map:
			if device_map[device]['isAndroid']:
				print(ADB_ARGS % (device,url,ANDROID_APP_ID))
				shlex.split(ADB_ARGS % (device,url,ANDROID_APP_ID))
				subprocess.call(shlex.split(ADB_ARGS % (device,url,ANDROID_APP_ID)), stderr=subprocess.PIPE, stdout=subprocess.PIPE)
	except Exception, e:
		print e


if __name__ == '__main__':
	dual_driving()
