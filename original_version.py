# Things user will have built in
import os
import json
import time
import logging

# Things the user will need to install
import cfscrape
import requests
from dhooks import Webhook
from bs4 import BeautifulSoup

# Initializing the logger
logging.basicConfig(
	level=logging.DEBUG,
	format="[%(asctime)s] %(levelname)s: %(message)s",
	datefmt="%H:%M:%S"
)

log = logging.getLogger(__name__)

log.info("Started the bumper")

# Get the user's config
with open('user.json', 'r') as file:
	config = json.loads(file.read())

# Validating the user.json file
if config['apikey'] == "":
	log.error("You don't have an API key set.")
	quit()
elif config['cookie'] == "":
	log.error("You don't have a cookie set.")
	quit()

# Start the scraper/session and check the user's API key
session = cfscrape.create_scraper(sess=requests.Session(), delay=5)
response = session.get("https://api.dawn.sh/bumper/checkkey.php", params={'apikey': config['apikey']})

if response.text != "":
	data = json.loads(response.text)
	if float(data['version']) != 2.7:
		log.error("Invalid version. Please message /dawn for assistance.")
		quit()
	else:
		log.info("Welcome back, " + data['user'])
else:
	log.error("Invalid user. Please message /dawn for assistance.")
	quit()

# Set the user's session so that they can be logged in w/o a user:pass
session.cookies['mybbuser'] = config['cookie']

# Saves debug file to the /debug/ folder
def debug(filename, response):
	# No debug files are made if the user is using Heroku.
	if not config['heroku']:
		with open('debug/' + filename + '.html', 'w+', encoding='utf-8') as file:
			file.write(response.text)

# Function to check various items, further explained within.
def check_site():
	log.info("Started basic checks")
	response = session.get("https://ogusers.com")
	soup = BeautifulSoup(response.text, 'html.parser')
	debug('check_site', response)

	# Checking if the user is correct
	user = soup.find_all('a', {'class': 'dropborder'})[-1].get('href').split('&uid=')[-1]
	
	response = session.get("https://api.dawn.sh/bumper/checkkey.php", params={'apikey': config['apikey']})
	data = json.loads(response.text)

	# If the user that is logged in is not the owner of the license key, they are reported.
	if int(user) != data['uid']:
		session.get("https://api.dawn.sh/bumper/report.php", params={'apikey': config['apikey'], 'username': int(user)})
		log.error("Incorrect user found. Your UID, IP and license key have been reported.")
		quit()
	# Checks to see if a CAPTCHA is present on the page.
	elif soup.find('div', {'class': 'g-recaptcha'}):
		log.error("CAPTCHA found. Please message /dawn for assistance.")
		return False
	# Runs 2 checks that function the same way. 1 to see if OGU's main page is down, and the other to check if the status code is 200 (up)
	elif not soup.find('img', {'src': 'logo.php'}):
		log.error("OGUsers is currently not functional [1]. Please message /dawn for assistance.")
		return False
	elif response.status_code != 200:
		log.error("OGUsers is currently not functional [2]. Please message /dawn for assistance.")
		return False
	else:
		log.info("Checks finished, all good.")
		return True

	response = session.get("https://api.dawn.sh/bumper/checkkey.php", params={'apikey': config['apikey']})
	if response.text != "":
		data = json.loads(response.text)
		if float(data['version']) != 2.6:
			log.error("Invalid version. Please message /dawn for assistance.")
			quit()
	else:
		log.error("Invalid user. Please message /dawn for assistance.")
		quit()

# Gets the username of the currently logged in user
def get_user():
	response = session.get("https://ogusers.com/usercp.php")
	soup = BeautifulSoup(response.text, 'html.parser')
	debug('get_user', response)

	return soup.find('div', {'class': 'usercp_container'}).find_all('a')[0].get_text()

# Creates and POSTs a webhook to either a Discord or a regular webhook.
def create_webhook(json):
	if config['alerts']['discord']:
		hook = Webhook(config['alerts']['url'])
		hook.send(json)
	else:
		session.post(config['alerts']['url'], json=json)

# Gets the latest reply to a thread with the provided TID.
def get_last_reply(thread):
	resp = session.get("https://ogusers.com/showthread.php?tid=" + str(thread) + "&action=lastpost&mode=threaded", allow_redirects=True)
	debug("getlastreply", resp)

	return str(resp.url).split('#pid')[-1]

# Gets the contents of the reply with the provided PID.
def get_reply_contents(thread, pid):
	resp = session.get("https://ogusers.com/showthread.php?tid=" + str(thread) + "&pid=" + str(pid) + "&mode=threaded")
	soup = BeautifulSoup(resp.text, "html.parser")
	debug("getreplycontents", resp)

	thread_name = soup.find('span', {'class': 'showthreadtopbar_size'}).get_text().replace('\n', '')
	author = soup.find("div", {"class": "postbit-avatar"}).find("a").get('href')

	return author, thread_name

# Checks to see if there are unread PMs, but doesn't read them.
def check_pms(read):
	resp = session.get("https://ogusers.com/private.php")
	soup = BeautifulSoup(resp.text, "html.parser")
	debug("checkpms", resp)

	pms = soup.find("form", {"action": "private.php"}).find('table', {'class': 'pborder'})

	for i in pms.find_all("tr"):
		if i.find("img", {"alt": "New Message"}):
			pmid = i.find("a", {"class": "new_pm"}).get('href').split("&pmid=")[-1]
			if not pmid in read:
				title = i.find("a", {"class": "new_pm"}).get_text()
				author = i.find_all('td', {'class': 'trow2_pm'})[1].find('span').get_text()

				json_data = {
					"owner": config['apikey'],
					"type": "pm",
					"author": author,
					"title": title,
					"link": "https://ogusers.com/private.php?action=read&pmid=" + pmid
				}

				json_data = json.dumps(json_data)
				create_webhook(json_data)
				read.append(pmid)

# Checks to see if the user has any alerts.
# Todo: read from the main page to avoid 'reading' the alerts.
def check_alerts(read):
	resp = session.get("https://ogusers.com/alerts.php")
	debug("checkalerts", resp)
	soup = BeautifulSoup(resp.text, "html.parser")

	alerts_find = soup.find("tbody", {"id": "latestAlertsListing"})
	all_alerts = alerts_find.find_all("tr")

	# If it finds more than 1 alert, it starts to log each alert's information.
	if len(all_alerts) > 1:
		for alert in all_alerts:
			try:
				alert_item = alert.find_all("td")
				author = alert_item[0].find("a", {"class": "avatar"}).get('href')
				thread = alert_item[1].find("strong").get_text()
				alertid = alert_item[1].find_all("a")[0].get('href').split("&id=")[-1]

				if not alertid in read:
					thread.replace('\n', '')
					json_data = {
						"owner": config['apikey'],
						"type": "alert",
						"author": author,
						"thread": thread,
						"link": "https://ogusers.com/alerts.php?action=view&id=" + alertid
					}

					json_data = json.dumps(json_data)
					create_webhook(json_data)
					read.append(alertid)
			except:
				pass

# Checks if the latest reply to a thread is from the owner
def check_posts(read):
	thread_file = open('threads.txt', 'r')

	for thread in thread_file.read().split("\n"):
		pid = get_last_reply(thread)
		author, thread_name = get_reply_contents(thread, pid)

		# If the author of the post is the same as the owner of the bumper, it makes a webhook.
		if author.lower() != get_user().lower():
			json_data = {
				"owner": config['apikey'],
				"type": "reply",
				"author": author,
				"thread": thread_name,
				"link": "https://ogusers.com/showthread.php?pid=" + pid
			}

			json_data = json.dumps(json_data)
			create_webhook(json_data)
			read.append(pid)

	thread_file.close()

# Checks PMs, alerts, and replies
def check_all(read):
	if config['alerts']['active']:
		log.info("Checking PMs")
		check_pms(read['pms'])
		log.info("Checking alerts")
		check_alerts(read['alerts'])
		log.info("Checking replies")
		check_posts(read['pids'])

# Bumps the provided thread
def bump(data):
	try:
		# If the default message does exist, it checks for a custom message before using the default message.
		if os.path.isfile('messages/{0}.txt'.format(data['thread'])):
			new_msg = open('messages/{0}.txt'.format(data['thread']))
			thread_msg = new_msg.read()
			new_msg.close()
		# Checks if the 'default' message exists. If it doesn't, it sets a built-in message.
		elif not os.path.isfile('messages/default.txt'):
			thread_msg = "Bumping this"
		# Finally, if a custom message is not provided, it uses the default message
		else:
			def_msg = open('messages/default.txt')
			thread_msg = def_msg.read()
			def_msg.close()

		# Does a GET request on the thread's reply page in order to get the post key, hash, etc.
		response = session.get("https://ogusers.com/newreply.php?tid=" + str(data['thread']))
		soup = BeautifulSoup(response.text, 'html.parser')
		debug('bump', response)

		post_key = soup.find('input', {'name': 'my_post_key'})
		post_hash = soup.find('input', {'name': 'posthash'})
		subject = soup.find('input', {'name': 'subject'})

		# Posting the data to the server, which will actually post the reply.
		response = session.post("https://ogusers.com/newreply.php", params={
			'action': 'do_newreply',
			'my_post_key': post_key.get('value'),
			'subject': subject.get('value'),
			'message': ' ' * data['spaces'] + thread_msg,
			'replyto': '0',
			'posthash': post_hash,
			'quoted_ids': 'Array',
			'tid': data['thread'],
			'postoptions[signature]': '1'
		});

		debug('after_bump', response)

		log.info("Bumped thread " + str(data['thread']))
	except Exception as e:
		print(e)
		log.error("There has been an error whilst bumping. Please message /dawn for assistance.")

def main():
	# Initialising the array to store all of the read posts, alerts, and messages.
	read = {'pms': [], 'alerts': [], 'pids': []}

	# Main program loop
	while True:
		while not check_site():
			time.sleep(60**2)

		# Checks all of the posts etc, and appends whatever is read to the "read" array, whilst also sending a webhook.
		check_all(read)

		# Opens the thread file, then appends each thread ID to an array, which is used in the bumping process.
		thread_file = open('threads.txt', 'r')
		threads = thread_file.read().split('\n')

		# Space count used to post the same message across different threads in lower than 30 minutes.
		spacecount = 0

		for thread in threads:
			spacecount += 1
			if thread != "":
				thread = thread.strip()
				# Puts the data required into a simpler, easily readable form.
				data = {
					'thread': thread,
					'spaces': spacecount
				}

				bump(data)
				log.info("Waiting before next bump")

				# Sleeps x seconds between posting. Different for each usergroup on the site.
				time.sleep(config['bumper']['timewait'])

		thread_file.close()

		# Once the bumping process is finished, it waits the delay in minutes.
		log.info("Finished bumping, waiting delay now.")
		time.sleep(config['bumper']['delay'] * 60)

if __name__ == "__main__":
	try:
		main()
	except KeyboardInterrupt:
		quit()