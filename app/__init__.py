from flask import Flask,request,render_template,redirect,session,url_for,flash
from flask.ext.session import Session
import sqlite3
import os
import json
import httplib2
import hashlib
from apiclient import discovery
from oauth2client import client
from functools import wraps
from urlparse import urlparse
# these lines are for debugging the google client API errors.
#import logging
#logging.basicConfig()

data_dir = os.environ.get('OPENSHIFT_DATA_DIR')

app = Flask(__name__)
app.debug = True
app.secret_key = os.urandom(24)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = data_dir + '/session'
Session(app)

@app.before_request
def before_request():
	host = urlparse(request.url).hostname
	if host == 'localhost':
		pass
	elif not request.is_secure:
		return redirect(request.url.replace("http://", "https://"))

def listCount(l):
	counts = []
	newList = []
	for position,value in enumerate(l):
		count = 0
		if value not in newList:
			newList.append(value)
			counts.append(1)
		else:
			for p,v in enumerate(newList):
				if value == v:
					counts[p] += 1
	
	for p,v in enumerate(counts):
		newList[p]['count'] = v
	
	return sorted(newList, reverse=True)


class logDB(object):
	def __init__(self):
		data_dir = os.environ.get('OPENSHIFT_DATA_DIR')
		self.conn = sqlite3.connect(data_dir + '/admin.db')
		self.c = self.conn.cursor()
		self.c.execute('CREATE TABLE IF NOT EXISTS admin(user_id INTEGER, date TEXT DEFAULT CURRENT_TIMESTAMP, item TEXT, value TEXT)')
		self.conn.commit()

	def entry(self,user_id,item,value):
		self.c.execute('INSERT INTO admin (user_id,item,value) VALUES (?,?,?)',(user_id,item,value,))
		self.conn.commit()

class shoeDB(object):

	def __init__(self):
		data_dir = os.environ.get('OPENSHIFT_DATA_DIR')
		self.conn = sqlite3.connect(data_dir + '/shoesize.db')
		self.c = self.conn.cursor()
		self.c.execute('CREATE TABLE IF NOT EXISTS makers(id INTEGER PRIMARY KEY, maker TEXT UNIQUE)')
		self.c.execute('CREATE TABLE IF NOT EXISTS lasts(id INTEGER PRIMARY KEY, last TEXT, maker_id INTEGER, FOREIGN KEY(maker_id) REFERENCES makers(id))')
		self.c.execute('CREATE TABLE IF NOT EXISTS sizes(id INTEGER PRIMARY KEY, size TEXT)')
		self.c.execute('CREATE TABLE IF NOT EXISTS widths(id INTEGER PRIMARY KEY, width TEXT)')
		self.c.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, emailhash TEXT UNIQUE)')
		self.c.execute('CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, user_id INTEGER, maker_id INTEGER, last_id INTEGER, size_id INTEGER, width_id INTEGER, '
			'FOREIGN KEY(user_id) REFERENCES users(id), '
			'FOREIGN KEY(maker_id) REFERENCES makers(id), '
			'FOREIGN KEY(last_id) REFERENCES lasts(id), '
			'FOREIGN KEY(size_id) REFERENCES sizes(id), '
			'FOREIGN KEY(width_id) REFERENCES widths(id))')
		self.conn.commit()

	def listMakers(self):
		results = []
		self.c.execute('SELECT id,maker FROM makers ORDER BY maker')
		for row in self.c.fetchall():
			results.append({'id':row[0],'maker':row[1]})
		return results

	def listLasts(self):
		results = []
		self.c.execute('SELECT lasts.id,last,makers.id,maker FROM lasts INNER JOIN makers ON makers.id=lasts.maker_id ORDER BY maker,last')
		for row in self.c.fetchall():
			results.append({'id':row[0],'last':row[1],'maker_id':row[2],'maker':row[3]})
		return results

	def listSizes(self):
		results = []
		self.c.execute('SELECT id,size FROM sizes')
		for row in self.c.fetchall():
			results.append({'id':row[0],'size':row[1]})
		return results

	def listWidths(self):
		results = []
		self.c.execute('SELECT id,width FROM widths')
		for row in self.c.fetchall():
			results.append({'id':row[0],'width':row[1]})
		return results

	def addMaker(self,maker):
		self.c.execute('SELECT * FROM makers WHERE maker=? COLLATE NOCASE',(maker,))
		if len(self.c.fetchall()) > 0:
			return False
		self.c.execute('INSERT INTO makers (maker) VALUES (?)',(maker,))
		self.conn.commit()
		return True

	def addLast(self,maker_id,last):
		self.c.execute('SELECT * FROM lasts WHERE maker_id=? AND last=? COLLATE NOCASE',(maker_id,last))
		if len(self.c.fetchall()) > 0:
			return False
		self.c.execute('INSERT INTO lasts (maker_id,last) VALUES (?,?)',(maker_id,last,))
		self.conn.commit()
		return True

	def addSize(self,size):
		self.c.execute('SELECT * FROM sizes WHERE size=? COLLATE NOCASE',(size,))
		if len(self.c.fetchall()) > 0:
			return False
		self.c.execute('INSERT INTO sizes (size) VALUES (?)',(size,))
		self.conn.commit()
		return True

	def addWidth(self,width):
		self.c.execute('SELECT * FROM widths WHERE width=? COLLATE NOCASE',(width,))
		if len(self.c.fetchall()) > 0:
			return False
		self.c.execute('INSERT INTO widths (width) VALUES (?)',(width,))
		self.conn.commit()
		return True

	def addEntry(self,user_id,maker_id,last_id,size_id,width_id):
		self.c.execute('SELECT * FROM entries WHERE user_id=? AND maker_id=? AND last_id=?',(user_id,maker_id,last_id,))
		if len(self.c.fetchall()) > 0:
			return False
		self.c.execute('INSERT INTO entries (user_id,maker_id,last_id,size_id,width_id) VALUES (?,?,?,?,?)',(user_id,maker_id,last_id,size_id,width_id,))
		self.conn.commit()
	
	def getUserID(self,emailhash):
		self.c.execute('SELECT id FROM users WHERE emailhash=?',(emailhash,))
		try:
			user_id = self.c.fetchone()[0]
		except:
			self.c.execute('INSERT INTO users (emailhash) VALUES (?)',(emailhash,))
			user_id = self.c.lastrowid
			self.conn.commit()
		return user_id

	def getUserEntries(self,user_id):
		results = []
		self.c.execute('SELECT maker,last,size,width,entries.id FROM entries '
			'INNER JOIN users ON entries.user_id=users.id '
			'LEFT JOIN makers ON entries.maker_id=makers.id '
			'LEFT JOIN lasts ON entries.last_id=lasts.id '
			'INNER JOIN sizes ON entries.size_id=sizes.id '
			'LEFT JOIN widths ON entries.width_id=widths.id '
			'WHERE users.id=? ORDER BY maker,last,size,width',(user_id,))
		for row in self.c.fetchall():
			entry = {}
			entry['maker'] = row[0]
			entry['last'] = row[1]
			entry['size'] = row[2]
			entry['width'] = row[3]
			entry['id'] = row[4]
			results.append(entry)
		return results

	def getAllEntries(self):
		results = {}
		self.c.execute('SELECT maker,last,size,width,users.id FROM entries '
			'INNER JOIN users ON entries.user_id=users.id '
			'LEFT JOIN makers ON entries.maker_id=makers.id '
			'LEFT JOIN lasts ON entries.last_id=lasts.id '
			'LEFT JOIN sizes ON entries.size_id=sizes.id '
			'LEFT JOIN widths ON entries.width_id=widths.id '
			'ORDER BY users.id,maker,last,size,width')
		for row in self.c.fetchall():
			entry = {}
			entry['maker'] = row[0]
			entry['last'] = row[1]
			entry['size'] = row[2]
			entry['width'] = row[3]
			uid = row[4]
			if uid not in results:
				results[uid] = []
			results[uid].append(entry)
		return results

	def deleteEntry(self,user_id,entry_id):
		self.c.execute('DELETE FROM entries WHERE user_id=? AND id=?',(user_id,entry_id,))
		self.conn.commit()

	def suggest(self,maker_id,last_id,size_id,width_id):
		results = []
		self.c.execute('SELECT maker,last,size,width FROM entries '
			'INNER JOIN users ON entries.user_id=users.id '
			'LEFT JOIN makers ON entries.maker_id=makers.id '
			'LEFT JOIN lasts ON entries.last_id=lasts.id '
			'INNER JOIN sizes ON entries.size_id=sizes.id '
			'LEFT JOIN widths ON entries.width_id=widths.id '
			'WHERE users.id IN '
				'(SELECT user_id FROM entries WHERE maker_id=? AND (last_id=? OR last_id is NULL) AND size_id=? AND (width_id=? OR width_id IS NULL)) '
			' ORDER BY maker,last,size,width',(maker_id,last_id,size_id,width_id,))
		for row in self.c.fetchall():
			entry = {}
			entry['maker'] = row[0]
			entry['last'] = row[1]
			entry['size'] = row[2]
			entry['width'] = row[3]
			results.append(entry)
		return listCount(results)

	def lastSuggest(self,maker_id,last_id):
		results = {}
		self.c.execute('SELECT maker,last,size,width,users.id FROM entries '
			'LEFT JOIN users ON entries.user_id=users.id '
			'LEFT JOIN makers ON entries.maker_id=makers.id '
			'LEFT JOIN lasts ON entries.last_id=lasts.id '
			'LEFT JOIN sizes ON entries.size_id=sizes.id '
			'LEFT JOIN widths ON entries.width_id=widths.id '
			'WHERE users.id IN '
				'(SELECT user_id FROM entries WHERE maker_id=? AND (last_id=? OR last_id is NULL)) '
			' ORDER BY maker,last,size,width',(maker_id,last_id,))
		for row in self.c.fetchall():
			entry = {}
			entry['maker'] = row[0]
			entry['last'] = row[1]
			entry['size'] = row[2]
			entry['width'] = row[3]
			uid = row[4]
			if uid not in results:
				results[uid] = []
			results[uid].append(entry)
		return results

	def getMaker(self,maker_id):
		self.c.execute('SELECT maker FROM makers WHERE id=?',(maker_id,))
		try: return self.c.fetchone()[0]
		except: return None

	def getLast(self,last_id):
		self.c.execute('SELECT last FROM lasts WHERE id=?',(last_id,))
		try: return self.c.fetchone()[0]
		except: return None

	def getSize(self,size_id):
		self.c.execute('SELECT size FROM sizes WHERE id=?',(size_id,))
		try: return self.c.fetchone()[0]
		except: return None

	def getWidth(self,width_id):
		self.c.execute('SELECT width FROM widths WHERE id=?',(width_id,))
		try: return self.c.fetchone()[0]
		except: return None

def auth_required(f):
	@wraps(f)
	def decorated(*args, **kwargs):
		if 'emailhash' in session:
			return f(*args, **kwargs)
		if 'credentials' not in session:
			return redirect(url_for('oauth2callback', next=request.path))
		credentials = client.OAuth2Credentials.from_json(session['credentials'])
		if credentials.access_token_expired:
			return redirect(url_for('oauth2callback', next=request.path))
		http_auth = credentials.authorize(httplib2.Http())
		oauth2_service = discovery.build('oauth2', 'v2', http=http_auth)
		collection = oauth2_service.userinfo()
		results = collection.get()
		try:
			response = results.execute()
		except:
			return redirect(url_for('oauth2callback', next=request.path))
		session['emailhash'] = hashlib.sha1(response['email']).hexdigest()
		return f(*args, **kwargs)
	return decorated

@app.route('/oauth2callback')
def oauth2callback():
	data_dir = os.environ.get('OPENSHIFT_DATA_DIR')
	flow = client.flow_from_clientsecrets(data_dir + '/client_secrets.json',scope='email',redirect_uri=url_for('oauth2callback', _external=True))
	if 'code' not in request.args:
		if 'next' in request.args:
			session['next'] = request.args.get('next')
		else:
			session['next'] = '/'
		auth_uri = flow.step1_get_authorize_url()
		return redirect(auth_uri)
	else:
		auth_code = request.args.get('code')
		credentials = flow.step2_exchange(auth_code)
		session['credentials'] = credentials.to_json()
		return redirect(session['next'])

@app.route('/', methods = ['GET','POST'])
def index():
	db = shoeDB()
	makerList = db.listMakers()
	lastList = db.listLasts()
	sizeList = db.listSizes()
	widthList = db.listWidths()
	if request.method == "GET":
		return render_template('index.html', makers=makerList,lasts=lastList,sizes=sizeList,widths=widthList)
	if request.method == "POST":
		maker_id = request.form.get('maker_id')
		if maker_id == "None":
			maker_id = None
		last_id = request.form.get('last_id')
		if last_id == "None":
			last_id = None
		size_id = request.form.get('size_id')
		if size_id == "None":
			size_id = None
		width_id = request.form.get('width_id')
		if width_id == "None":
			width_id = None
		action = request.form.get('action')
		if action == 'suggest':
			entry = {'maker':db.getMaker(maker_id),'last':db.getLast(last_id),'size':db.getSize(size_id),'width':db.getWidth(width_id)}
			suggestions = db.suggest(maker_id,last_id,size_id,width_id)
			return render_template('suggest.html', entry=entry, suggestions=suggestions)
		elif action == 'lastSuggest':
			entry = {'maker':db.getMaker(maker_id),'last':db.getLast(last_id)}
			suggestions = db.lastSuggest(maker_id,last_id)
			return render_template('lastSuggest.html', entry=entry, suggestions=suggestions)

@app.route('/admin', methods = ['GET','POST'])
@auth_required
def admin():
	db = shoeDB()
	user_id = db.getUserID(session.get('emailhash'))
	l = logDB()
	if request.method == "POST":
		if request.form.get('add') == 'maker':
			maker = request.form.get('maker').strip()
			db.addMaker(maker)
			l.entry(user_id,'maker',maker)
		if request.form.get('add') == 'last':
			maker_id = request.form.get('maker_id').strip()
			last = request.form.get('last')
			db.addLast(maker_id,last)
			l.entry(user_id,'last',last)
		if request.form.get('add') == 'size':
			size = request.form.get('size').strip()
			db.addSize(size)
			l.entry(user_id,'size',size)
		if request.form.get('add') == 'width':
			width = request.form.get('width').strip()
			db.addWidth(width)
			l.entry(user_id,'width',width)
	makerList = db.listMakers()
	lastList = db.listLasts()
	sizeList = db.listSizes()
	widthList = db.listWidths()
	return render_template('admin.html', makers=makerList,lasts=lastList,sizes=sizeList,widths=widthList)

@app.route('/submit', methods = ['GET','POST'])
@auth_required
def submit():
	db = shoeDB()
	user_id = db.getUserID(session.get('emailhash'))
	if request.method == "POST":
		if request.form.get('action') == 'add':
			maker_id = request.form.get('maker_id')
			if maker_id == "None":
				maker_id = None
			last_id = request.form.get('last_id')
			if last_id == "None":
				last_id = None
			size_id = request.form.get('size_id')
			if size_id == "None":
				size_id = None
			width_id = request.form.get('width_id')
			if width_id == "None":
				width_id = None
			if db.addEntry(user_id,maker_id,last_id,size_id,width_id) == False:
				flash("You may not have two entries with the same maker/last combination")
		if request.form.get('action') == 'delete':
			entry_id = request.form.get('id')
			db.deleteEntry(user_id,entry_id)
	makerList = db.listMakers()
	lastList = db.listLasts()
	sizeList = db.listSizes()
	widthList = db.listWidths()
	userEntries = db.getUserEntries(user_id)
	return render_template('submit.html', makers=makerList,lasts=lastList,sizes=sizeList,widths=widthList,userEntries=userEntries)

@app.route('/browse')
def browse():
	db = shoeDB()
	entries = db.getAllEntries()
	return render_template('browse.html', entries=entries)
	


