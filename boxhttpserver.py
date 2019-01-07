#!/usr/bin/env python3

from __future__ import with_statement

import os
import sys
import errno
import argparse
import code
import pprint
import json
import time
import urllib3
import urllib.parse
import certifi
import mimetypes
import threading
import uuid

from socketserver import ThreadingMixIn
from http.server import BaseHTTPRequestHandler, HTTPServer, SimpleHTTPRequestHandler 
import logging
from boxsdk import OAuth2, Client

TOKENS_DIR="/etc/boxhttpproxy/tokens"
TOKENS_FILE=TOKENS_DIR+"/tokens"
APP_CLIENTID="3wvqtoo6dbgeka2xctl1u6hx7btws16c"
APP_SECRET="gzU3R6z5AxkMD6DZ4GzvMtBxr9by7pHy"
APP_ACCESS_TOKEN=""
FILESYSTEM_REFRESH_TIME=600
#chunk_size = 65536
#chunk_size = 1048576
chunk_size = 5242880
#chunk_size = 8388608
#chunk_size = 15728640

loglevel = logging.DEBUG

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
		'content': []
	}
}

http_pool_headers = urllib3.make_headers(
    keep_alive=True, 
    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36"
    )

http_pool_mgr = urllib3.PoolManager(maxsize=50,
	num_pools=50,
    headers=http_pool_headers,
    block=False,
    cert_reqs='CERT_REQUIRED',
    ca_certs=certifi.where())
#urllib3.disable_warnings()
#logging.captureWarnings(False)



class S(SimpleHTTPRequestHandler):
	def log_message(self, format, *args):
		logging.error("%s - - [%s] %s" % (self.client_address[0], 
			self.log_date_time_string(), 
			format%args))
	def do_GET(self):
		# check if folder_cache is fresh
		global folder_cache_last_refresh, folder_cache, FILESYSTEM_REFRESH_TIME
		request_id = uuid.uuid4()
		response = ""
		response_code = 200
		logging.info("%s: %s: GET request, Path: %s Threads: %d Headers: %s", request_id, str(time.time()), str(self.path), threading.active_count(), pprint.saferepr(str(self.headers)))
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
					logging.info("%s: %s: GET request, Path: %s Redirect Folder with / at the end", request_id, str(time.time()), str(self.path))
					self.send_response(301)
					self.send_header('Content-Type', 'text/html')
					#self.send_header('Connection', 'close')
					self.send_header('Location', path+"/")
					self.send_header('Transfer-Encoding', 'chunked')
					self.send_header('Last-Modified', time.mktime(time.strptime(folder_cache[searchpath]["modified_at"][:-6], "%a, %d %b %Y %H:%M:%S GMT")))
					self.end_headers()
					response='''
						<html>
						<head>
						<title>Moved</title>
						</head>
						<body>
						<h1>Moved</h1>
						<p>This page has moved to <a href="%s">%s</a>.</p>
						<p>Request id: %s</p>
						</body>
						</html>
					''' % (path+"/", path+"/", request_id)
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
				self.send_response(response_code)
				self.send_header('Content-Length', len(response))
				self.send_header('Accept-Ranges', 'bytes')
				#self.send_header('Connection', 'close')
				self.send_header('Content-Type', 'text/html')
				logging.debug("%s: %s: Last-Modified Header: ", request_id, str(time.time()), str(self.path), time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(folder_cache[item]["st_mtime"])))
				self.send_header('Last-Modified', str(time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(folder_cache[item]["st_mtime"]))))
				self.end_headers()
				start_dl = time.time()
				self.wfile.write(response.encode('UTF-8'))
				end_dl = time.time()
				elapse_dl = end_dl-start_dl
				logging.info("%s: %s: GET request, Path: %s Ending Folder Download, Elapsed:%f", request_id, str(time.time()), str(self.path), elapse_dl)
				return
			else:
				try:
					logging.info("%s: %s: GET request, Path: %s File", request_id, str(time.time()), str(self.path))
					start_dl = time.time()
					boxheaders = { 
						'Authorization': 'Bearer '+oauth.access_token,
						'Connection': 'keep-alive', 
						'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36' 
					}
					startByte = 0
					endByte = int(folder_cache[searchpath]["st_size"])-1
					if "Range" in self.headers:
						check_headers = check_request_headers(self, searchpath, request_id)
						if check_headers[0] == "-1":
							return
						boxheaders["Range"] = check_headers[0]
						startByte = check_headers[1]
						endByte = check_headers[2]
					boxurl = 'https://api.box.com/2.0/files/'+str(folder_cache[path]["boxid"])+'/content'
					stream_file_from_box(boxurl, request_id, self, response_code, boxheaders, searchpath, startByte, endByte)
				except:
					e = sys.exc_info()
					logging.error("%s: %s: Exception: %s Range:%s Detail:%s", request_id, str(time.time()), boxurl, boxheaders["Range"], pprint.saferepr(e))
		else:
			self.send_response(404)
			self.send_header('Content-type', 'text/html')
			self.send_header('Connection', 'close')
			self.end_headers()
			self.wfile.write("File not found".encode('utf-8'))
		return


	def do_HEAD(self):
		global folder_cache_last_refresh, folder_cache, FILESYSTEM_REFRESH_TIME
		request_id = uuid.uuid4()
		response = ""
		logging.info("%s: %s: HEAD request, Path: %s Headers: %s", request_id, str(time.time()), str(self.path), pprint.saferepr(str(self.headers)))
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
				logging.info("%s: %s: HEAD request, Path: %s return folder info", request_id, str(time.time()), str(self.path))
				self.send_header('Content-Type', 'text/html;charset=UTF-8')
				self.send_header('Last-Modified', str(time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(folder_cache[searchpath]["st_mtime"]))))
			if folder_cache[searchpath]["type"] == "file":
				logging.info("%s: %s: HEAD response, Path: %s return file info: Content-Type: %s, Content-Length:%s", request_id, str(time.time()), str(self.path), folder_cache[searchpath]["mime"], str(folder_cache[searchpath]["st_size"]))
				self.send_header('Content-Type', folder_cache[searchpath]["mime"])
				self.send_header('Content-Length', folder_cache[searchpath]["st_size"])
				self.send_header('Last-Modified', str(time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(folder_cache[searchpath]["st_mtime"]))))
			self.end_headers()

def check_request_headers(connection, searchpath, request_id):
	rangeStr = connection.headers["Range"].replace("bytes=", "").replace("\n", "")
	logging.debug("%s: %s: check_request_headers rangeStr substitution: %s", request_id, str(time.time()), rangeStr)
	#response_code = 206
	rangeSplit = rangeStr.split("-")
	startByte = 0
	endByte = int(folder_cache[searchpath]["st_size"])-1
	if len(rangeSplit) > 1:
		startByte = int(rangeSplit[0])
		if startByte > (int(folder_cache[searchpath]["st_size"])-1):
			connection.send_response(416)
			connection.send_header('Content-Type', 'text/html')
			connection.send_header('Connection', 'close')
			connection.end_headers()
			response='''
				<html>
				<head>
				<title>416 Range Not Satisfiable</title>
				</head>
				<body>
				<h1>416 Range Not Satisfiable</h1>
				<p>Request out of range (startByte) was %d should be less than %d.</p>
				<p>Request id: %s</p>
				</body>
				</html>
			''' % (startByte, int(folder_cache[searchpath]["st_size"])-1, request_id)
			logging.info("%s: %s: Box request: %s Range:%s Status: 416", request_id, str(time.time()), boxurl, connection.headers["Range"])
			connection.wfile.write(bytes(response, 'UTF-8'))
			return "-1"
		if rangeSplit[1] != "":
			endByte = int(rangeSplit[1])
		if endByte > (int(folder_cache[searchpath]["st_size"])-1):
			connection.send_response(416)
			connection.send_header('Content-Type', 'text/html')
			connection.send_header('Connection', 'close')
			connection.end_headers()
			response='''
				<html>
				<head>
				<title>416 Range Not Satisfiable</title>
				</head>
				<body>
				<h1>416 Range Not Satisfiable</h1>
				<p>Request out of range (endByte) was %d should be less than %d.</p>
				<p>Request id: %s</p>
				</body>
				</html>
			''' % (endByte, int(folder_cache[searchpath]["st_size"])-1, request_id)
			connection.wfile.write(bytes(response, 'UTF-8'))
			logging.info("%s: %s: Box request: %s Range:%s Status: 416", request_id, str(time.time()), boxurl, connection.headers["Range"])
			return "-1"
	else:
		startByte = rangeSplit[0]
		if startByte > (int(folder_cache[searchpath]["st_size"])-1):
			connection.send_response(416)
			connection.send_header('Content-Type', 'text/html')
			connection.send_header('Connection', 'close')
			connection.end_headers()
			response='''
				<html>
				<head>
				<title>416 Range Not Satisfiable</title>
				</head>
				<body>
				<h1>416 Range Not Satisfiable</h1>
				<p>Request out of range (startByte) was %d should be less than %d.</p>
				<p>Request id: %s</p>
				</body>
				</html>
			''' % (startByte, int(folder_cache[searchpath]["st_size"])-1, request_id)
			logging.info("%s: %s: Box request: %s Range:%s Status: 416", request_id, str(time.time()), boxurl, connection.headers["Range"])
			connection.wfile.write(bytes(response, 'UTF-8'))
			return "-1"
		endByte = int(folder_cache[searchpath]["st_size"])-1
	returned_val = "bytes="+str(startByte)+"-"+str(endByte)
	logging.debug("%s: %s: check_request_headers returning: %s", request_id, str(time.time()), returned_val)
	return returned_val, startByte, endByte

def stream_file_from_box(boxurl, request_id, connection, response_code, boxheaders, searchpath, startByte, endByte):
	logging.info("%s: %s: Box request: %s headers:%s", request_id, str(time.time()), boxurl, pprint.saferepr(boxheaders))	
	start_dl = time.time()
	chunk_cnt = 1
	downloaded = 0
	connection.send_response(response_code)
	connection.send_header('Content-Type', folder_cache[searchpath]["mime"])
	connection.send_header('Last-Modified', str(time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.localtime(folder_cache[searchpath]["st_mtime"]))))
	if "Range" in boxheaders:
		content_length = (endByte - startByte)+1
		connection.send_header('Content-Length', str(content_length))
		client_range_response = boxheaders["Range"].replace("=", " ")+"/"+str(folder_cache[searchpath]["st_size"])
		connection.send_header('Content-Range', client_range_response)
		connection.send_header('Connection', 'keep-alive')
		logging.info("%s: %s: Client response headers: Content-Length: %s Content-Range:%s", request_id, str(time.time()), str(content_length), client_range_response)
	else:
		connection.send_header('Content-Length', str(folder_cache[searchpath]["st_size"]))
	connection.end_headers()
	try:
		r_dl = http_pool_mgr.request('GET', boxurl, headers=boxheaders, preload_content=False)
		if r_dl.status == 200 or r_dl.status == 206:
			logging.info("%s: %s: Box request success: %s Boxheaders:%s Status: %s", request_id, str(time.time()), boxurl, boxheaders, str(r_dl.status))
			for chunk in r_dl.stream(chunk_size):
				logging.info("%s: %s: Box response chunk: %s Boxheaders:%s chunk_cnt:%s lengthOfByte:%s", request_id, str(time.time()), boxurl, boxheaders, str(chunk_cnt), str(startByte+(chunk_size*chunk_cnt)))
				downloaded += len(chunk)
				chunk_cnt += 1
				try:
					connection.wfile.write(chunk)
					connection.wfile.flush()
				except:
					e = sys.exc_info()
					logging.error("%s: %s: Client Exception Detail:%s", request_id, str(time.time()), pprint.saferepr(e))
					break
		else:
			logging.info("%s: %s: Box request failed: %s Boxheaders:%s Status: %s", request_id, str(time.time()), boxurl, boxheaders, str(r_dl.status))
		r_dl.release_conn()
		end_dl = time.time()
		elapse_dl = end_dl-start_dl
	except:
		e = sys.exc_info()
		logging.error("%s: %s: Box Exception Detail:%s", request_id, str(time.time()), pprint.saferepr(e))
		r_dl.release_conn()
		end_dl = time.time()
		elapse_dl = end_dl-start_dl
	logging.info("%s: %s: Box request: %s Boxheaders:%s Status: %d Released, Elapsed:%f Downloaded(Chunks):%d bytes Downloaded(b):%d bytes", request_id, str(time.time()), boxurl, boxheaders, r_dl.status, elapse_dl, (chunk_cnt*chunk_size), downloaded)
	return


def populateFolderCache(path):
	global folder_cache, oauth, client, contentTypes
	logging.info("populateFolderCache " +path)
	folder_id = folder_cache[path]["boxid"]

	translated_path = ""
	if path != "/":
		translated_path = path

	folder_query = client.folder(folder_id).get_items(limit=1000,fields=['id','size','type','created_at','modified_at','name'])
	length = int(len(folder_query))
	logging.info(str(time.time())+" populateFolderCache " +path+" len: "+str(length))
	item = 0
	while item < length:
		#self.log("readdir item "+str(item))
		fileItem = folder_query[item]
		newPath = translated_path+"/"+fileItem["name"]
		if newPath not in folder_cache:
			logging.debug("populateFolderCache " +newPath+" create new node in list")
			folder_cache[newPath] = dict()
		if fileItem["type"] == "folder":
			folder_cache[newPath]["boxid"] = fileItem["id"]
			folder_cache[newPath]["type"] = fileItem["type"]
			folder_cache[newPath]['st_size'] = 4096
			folder_cache[newPath]['content'] = []
			folder_cache[newPath]["st_mtime"] = time.mktime(time.strptime(fileItem["modified_at"][:-6], "%Y-%m-%dT%H:%M:%S"))
			populateFolderCache(newPath)
		if fileItem["type"] == "file":
			folder_cache[newPath]['st_size'] = fileItem["size"]
			folder_cache[newPath]["boxid"] = fileItem["id"]
			folder_cache[newPath]["type"] = fileItem["type"]
			folder_cache[newPath]["st_mtime"] = time.mktime(time.strptime(fileItem["modified_at"][:-6], "%Y-%m-%dT%H:%M:%S"))
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
	global folder_cache_last_refresh, loglevel
	logging.basicConfig(stream=sys.stdout,level=loglevel)
	server_address = ('', port)
	handler_class.server_version = "nginx/1.14.0"
	handler_class.sys_version = "(Ubuntu)"
	#handler_class.protocol_version = "HTTP/1.1"  # this doesn't work correctly
	httpd = ThreadingSimpleServer(server_address, S)	# multi-threaded
	#httpd = HTTPServer(server_address, S)   			# single-threaded
	logging.info(str(time.time())+' populateFolderCache first time...\n')
	populateFolderCache("/")
	folder_cache_last_refresh = time.time()
	logging.info(str(time.time())+' Starting httpd...\n')
	# set urllib3.logging
	logging.getLogger("urllib3").setLevel(logging.WARNING)
	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass
	httpd.server_close()
	logging.info(str(time.time())+' Stopping httpd...\n')

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

	if len(argv) == 2:
		if str(argv[1]) == "firstrun":
			print ("First run exiting")
			sys.exit()

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
	#code.interact(local=locals())
