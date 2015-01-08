=== What? ===

dualdriver.py: this script controls two browser instances, for example Firefox OS on a Flame and a desktop browser. It helps you do bug triage by loading bugs and launching the relevant URLs on the phone automatically

Usage:
 * have adb setup, the Python marionette client, and a nightly build of Firefox OS with Marionette enabled
 * You also need a running Firefox Desktop instance with Marionette enabled, listening on localhost:2828 (the default)
 * Make sure you are logged in to the bug tracker you're using in the Firefox Desktop instance
 * run "adb forward tcp:2829 tcp:2828"
 * run "python dualdriver.py -u " followed by the URL to a Bugzilla search you want to go through

find-contact-and-comment.py: this script tries to find contact points for bugs on webcompat.com and add suitable comments (it lets you edit and submit the comments manually)

Usage: 
* Extract CSV data for a suitable list of bugs (I'll make this run off a bug search too, later - this is an older experiment so that feature hasn't reached it yet)
* Edit the script to set dirname and filename variables (I know, I'll fix this too)
* make sure you're logged in to webcompat.com in the Marionette client
* run "python find-contacts-and-comment.py"
