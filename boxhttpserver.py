#!/usr/bin/env python3

from __future__ import with_statement

import os
import sys
import errno
import argparse
import code
import pprint
import json
import stat
import fuse
import fusepy
import time
import urllib3
import urllib.parse
import certifi
import mimetypes

from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler 
import logging
from boxsdk import OAuth2, Client

TOKENS_DIR="./tokens"
TOKENS_FILE=TOKENS_DIR+"/tokens"
APP_CLIENTID="3wvqtoo6dbgeka2xctl1u6hx7btws16c"
APP_SECRET="gzU3R6z5AxkMD6DZ4GzvMtBxr9by7pHy"
APP_ACCESS_TOKEN=""
FILESYSTEM_REFRESH_TIME=600

oauth = None
client = None
contentTypes = None

start_time = time.time()

folder_cache_last_refresh=0
folder_cache = { 
	'/': {
		'boxid': 0,
		'type': 'folder',
		'st_size': 4096,
		'st_ctime': start_time,
		'st_mtime': start_time,
		'content': []
	}
}

http_pool_headers = urllib3.make_headers(
    keep_alive=True, 
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36"
    )

http_pool_mgr = urllib3.PoolManager(10,
    headers=http_pool_headers,
    block=False,
    cert_reqs='CERT_REQUIRED',
    ca_certs=certifi.where())

class S(SimpleHTTPRequestHandler):
	def do_GET(self):
		# check if folder_cache is fresh
		global folder_cache_last_refresh, folder_cache, FILESYSTEM_REFRESH_TIME
		response = ""
		logging.info("GET request, Path: %s Headers: %s\n", str(self.path), pprint.saferepr(str(self.headers)))
		if (time.time() - folder_cache_last_refresh) > FILESYSTEM_REFRESH_TIME:
			folder_cache_last_refresh = time.time()
			populateFolderCache("/")
		path = urllib.parse.unquote(self.path)
		searchpath = path
		if path != "/" and path.endswith("/"):
			searchpath = path[:-1]
		if searchpath in folder_cache:
			if folder_cache[searchpath]["type"] == "folder":
				if path.endswith("/") == False:
					# redirect to path with / at the end
					logging.info("GET request, Path: %s Redirect with / at the end\n", str(self.path))
					self.send_response(301)
					self.send_header('Content-Type', 'text/html')
					self.send_header('Connection', 'close')
					self.send_header('Location', path+"/")
					self.send_header('Transfer-Encoding', 'chunked')
					self.end_headers()
					response='''
						<html>
						<head>
						<title>Moved</title>
						</head>
						<body>
						<h1>Moved</h1>
						<p>This page has moved to <a href="%s">%s</a>.</p>
						</body>
						</html>
					''' % (path+"/", path+"/")
					self.wfile.write(bytes(response.format(self.path), 'UTF-8'))
					return
				# build response
				index_display_path = path
				response = "<html>\r\n<head><title>Index of "+path+"</title></head>\r\n<body bgcolor=\"white\">\r\n"
				response += "<h1>Index of "+index_display_path+"</h1><hr><pre>"
				if path != "/":
					response += "<a href=\"../\">../</a>\r\n"
				for item in folder_cache[searchpath]["content"]:
					filename = item.split("/")[-1]
					item_size = folder_cache[item]["st_size"]
					displayfilename = filename
					if folder_cache[item]["type"] == "folder":
						filename += "/"
						displayfilename += "/"
						item_size = "-"
					if len(displayfilename) > 47:
						displayfilename = displayfilename[:47]+"..&gt;"
					response += "<a href=\"%s\">%-55s%s%20s\r\n" % (urllib.parse.quote(filename), displayfilename+"</a> ", time.strftime('%d-%b-%Y %H:%M', time.localtime(folder_cache[item]["st_mtime"])), item_size)
				response += "</pre><hr></body>\r\n</html>\r\n"
				self.send_response(200)
				self.send_header('Content-Length', len(response))
				self.send_header('Accept-Ranges', 'bytes')
				self.send_header('Connection', 'close')
				self.send_header('Content-Type', 'text/html')
				self.end_headers()
				start_dl = time.time()
				self.wfile.write(response.encode('UTF-8'))
				end_dl = time.time()
				elapse_dl = end_dl-start_dl
				logging.info("GET request, Path: %s Ending Download, Elapsed:%f", str(self.path), elapse_dl)
				return
			else:
				self.send_response(200)
				self.send_header('Content-Type', folder_cache[searchpath]["mime"])
				self.send_header('Content-Length', folder_cache[searchpath]["st_size"])
				self.end_headers()
				logging.info("GET request,\nPath: %s\nStarting Download", str(self.path))
				start_dl = time.time()
				boxheaders = { 
					'Authorization': 'Bearer '+oauth.access_token,
					'Connection': 'keep-alive', 
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36' 
				}
				if "Range" in self.headers:
					boxheaders["Range"] = self.headers["Range"]
				boxurl = 'https://api.box.com/2.0/files/'+str(folder_cache[path]["boxid"])+'/content'
				logging.info("Box request: %s\nheaders:%s\n", boxurl, pprint.saferepr(boxheaders))	
				r_dl = http_pool_mgr.request('GET', boxurl, headers=boxheaders, preload_content=False)
				for chunk in r_dl.stream(524288):
					try:
						self.wfile.write(chunk)
					except:
						e = sys.exc_info()[0]
						logging.info("Box request: %s Range:%s Exception:%s", boxurl, boxheaders["Range"], e)
						break;
				#r_dl.release_conn()
				logging.info("Box request: %s Range:%s Status: %d Released", boxurl, boxheaders["Range"], r_dl.status)
				end_dl = time.time()
				elapse_dl = end_dl-start_dl
				logging.info("GET request,\nPath: %s\nEnding Download, Elapsed:%f", str(self.path), elapse_dl)
				return
		else:
			self.send_response(404)
			self.send_header('Content-type', 'text/html')
			self.send_header('Connection', 'close')
			self.end_headers()
			self.wfile.write("File not found".encode('utf-8'))
		return

	def do_HEAD(self):
		global folder_cache_last_refresh, folder_cache, FILESYSTEM_REFRESH_TIME
		response = ""
		logging.info("HEAD request, Path: %s Headers: %s\n", str(self.path), pprint.saferepr(str(self.headers)))
		if (time.time() - folder_cache_last_refresh) > FILESYSTEM_REFRESH_TIME:
			folder_cache_last_refresh = time.time()
			populateFolderCache("/")
		path = urllib.parse.unquote(self.path)
		searchpath = path
		if path != "/" and path.endswith("/"):
			searchpath = path[:-1]
		if searchpath in folder_cache:
			self.send_response(200)
			self.send_header('Connection', 'close')
			if folder_cache[searchpath]["type"] == "folder":
				self.send_header('Accept-Ranges', 'bytes')
				logging.info("HEAD request, Path: %s return folder\n", str(self.path))
				self.send_header('Content-Type', 'text/html;charset=UTF-8')
			if folder_cache[searchpath]["type"] == "file":
				logging.info("HEAD request, Path: %s return file\n", str(self.path))
				self.send_header('Content-Type', folder_cache[searchpath]["mime"])
				self.send_header('Content-Length', folder_cache[searchpath]["st_size"])
			self.end_headers()

def populateFolderCache(path):
	global folder_cache, oauth, client, contentTypes
	logging.info("populateFolderCache " +path)
	folder_id = folder_cache[path]["boxid"]

	translated_path = ""
	if path != "/":
		translated_path = path

	folder_query = client.folder(folder_id).get_items(limit=1000,fields=['id','size','type','created_at','modified_at','name'])
	length = int(len(folder_query))
	logging.info("populateFolderCache " +path+" len: "+str(length))
	item = 0
	while item < length:
		#self.log("readdir item "+str(item))
		fileItem = folder_query[item]
		newPath = translated_path+"/"+fileItem["name"]
		folder_cache[newPath] = dict()
		if fileItem["type"] == "folder":
			folder_cache[newPath]["boxid"] = fileItem["id"]
			folder_cache[newPath]["type"] = fileItem["type"]
			folder_cache[newPath]["st_ctime"] = time.mktime(time.strptime(fileItem["created_at"], "%Y-%m-%dT%H:%M:%S-07:00"))
			folder_cache[newPath]["st_mtime"] = time.mktime(time.strptime(fileItem["modified_at"], "%Y-%m-%dT%H:%M:%S-07:00"))
			folder_cache[newPath]['st_size'] = 4096
			folder_cache[newPath]['content'] = []
			populateFolderCache(newPath)
		if fileItem["type"] == "file":
			folder_cache[newPath]['st_size'] = fileItem["size"]
			folder_cache[newPath]["boxid"] = fileItem["id"]
			folder_cache[newPath]["type"] = fileItem["type"]
			folder_cache[newPath]["st_ctime"] = time.mktime(time.strptime(fileItem["created_at"], "%Y-%m-%dT%H:%M:%S-07:00"))
			folder_cache[newPath]["st_mtime"] = time.mktime(time.strptime(fileItem["modified_at"], "%Y-%m-%dT%H:%M:%S-07:00"))
			# work out mimetype
			extension = "."+newPath.split(".")[-1]
			if extension in contentTypes:
				folder_cache[newPath]["mime"] = contentTypes[extension]
			else:
				logging.info("exension not found "+extension)
		folder_cache[path]['content'].append(newPath)
		item = item + 1


class ThreadingSimpleServer(ThreadingMixIn, HTTPServer):
    pass

def run(server_class=HTTPServer, handler_class=S, port=8080):
	global folder_cache_last_refresh
	logging.basicConfig(level=logging.INFO)
	server_address = ('', port)
	handler_class.server_version = "nginx/1.14.0"
	handler_class.sys_version = "(Ubuntu)"
	#handler_class.protocol_version = "HTTP/1.1"  # this doesn't work correctly
	httpd = ThreadingSimpleServer(server_address, handler_class)
	logging.info('populateFolderCache first time...\n')
	populateFolderCache("/")
	folder_cache_last_refresh = time.time()
	logging.info('Starting httpd...\n')
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass
	httpd.server_close()
	logging.info('Stopping httpd...\n')

def store_tokens(access_token, refresh_token):
    # store the tokens at secure storage (e.g. Keychain)
    print ("store token\naccess_token: "+access_token+"\nrefresh_token:"+refresh_token)
    data = { "access_token": access_token,
            "refresh_token": refresh_token
    }
    with open(TOKENS_FILE, "w") as write_file:
        json.dump(data, write_file)


def authenticate_with_box():
    print ("Authenticate with box")
    client = None
    oauth = OAuth2(
        client_id=APP_CLIENTID,
        client_secret=APP_SECRET,
        store_tokens=store_tokens,
    )

    auth_url, csrf_token = oauth.get_authorization_url('https://github.com/r00k135/boxhttpproxy/wiki/authenticated')
    print ("Navigate to this URL in a browser: "+auth_url)
    auth_code = input("Type the value from the result URL and the code= parameter in here: ")
    APP_ACCESS_TOKEN, refresh_token = oauth.authenticate(auth_code)    
    return oauth


if __name__ == '__main__':
	from sys import argv
	# check .tokens directory exists
	if os.path.exists(TOKENS_DIR) == False:
		try:
			os.makedirs(TOKENS_DIR)
		except OSError:
			logging.info ("unable to create "+TOKENS_DIR+" directory")
			exit (1)
	# See if token file exists
	if os.path.isfile(TOKENS_FILE):
		print ("Loading saved access_token: "+TOKENS_FILE)
		with open(TOKENS_FILE) as data_file:    
			data = json.load(data_file)
			#print (pprint.pprint(data))
			try:
				APP_ACCESS_TOKEN = data["access_token"]
				APP_REFRESH_TOKEN = data["refresh_token"]
				oauth = OAuth2(APP_CLIENTID, APP_SECRET, access_token=APP_ACCESS_TOKEN, refresh_token=APP_REFRESH_TOKEN, store_tokens=store_tokens)
				#if (oauth.access_token != APP_ACCESS_TOKEN):
			except e:
				print ("Error open tokens file: "+e)
	else:
		oauth = authenticate_with_box() 
	print ("Loading mimetypes")
	mimetype_locations=['/etc/mime.types']
	contentTypes = mimetypes.types_map
	for location in mimetype_locations:
		if os.path.exists(location):
			more = mimetypes.read_mime_types(location)
			if more is not None:
				contentTypes.update(more)

	print ("Starting box client")
	client = Client(oauth)
	me = client.user(user_id='me').get()
	print ('user_login: ' + me['login'])


	if len(argv) == 2:
		run(port=int(argv[1]))
	else:
		run()
	# debug terminal at end
	code.interact(local=locals())