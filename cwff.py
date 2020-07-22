import os, requests, concurrent.futures, sys, time, datetime, re, tldextract, argparse
from bs4 import BeautifulSoup as bs
from user_agent import generate_user_agent
from urllib import parse
import api_keys, filter_model
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class color:
	reset     = '\033[0m'
	green     = reset + '\033[32m'
	blue      = reset + '\033[94m'
	red       = reset + '\033[31m'
	white     = reset + '\x1b[37m'
	magneta   = reset + '\x1b[35m'
	cyan      = reset + '\x1b[36m'
	Bold      = "\033[1m"
	underline = "\033[4m"

class collector:
	def __init__(self, domain, threads=1000, recursion=False):
		self.scheme = parse.urlparse(domain).scheme or "http"
		self.__parsed_domain = tldextract.extract(domain)
		if self.__parsed_domain.subdomain:
			self.domain     = ".".join(
				[
					self.__parsed_domain.subdomain,
					self.__parsed_domain.domain,
					self.__parsed_domain.suffix
				]
			)
		else:
			self.domain = self.__parsed_domain.registered_domain
		self.__headers                = {
			'Accept': 'text/html,application/xhtml+xml,application/xml,application/json;q=0.9,image/webp,*/*;q=0.8',
			'Accept-Language': 'en-US,en;q=0.8', 'Accept-Encoding': 'gzip, deflate', 'User-agent': generate_user_agent(),
			'Cache-Control': 'max-age=0', 'Upgrade-Insecure-Requests': '1', 'Connection': 'close'
		}
		self.endpoints                    = set()
		self.parameters                   = set()
		self.js_files                     = []
		self.wayback_urls                 = []
		self.builtwith_connected_websites = set()
		self.recursion                    = recursion
		# Regex is borrowed from https://github.com/GerbenJavado/LinkFinder but mine m ThreadPoolExecutorodified/improved :)
		self.endpoint_regex = re.compile(r"""
			(%s(?:"|')
			(?:
				((?:/|\.\./|\./)
				[^"'><,;| *()(%%$^/\\\[\]]
				[^"'><,;|()]{1,})
				|
				([a-zA-Z0-9_\-/]{1,}/
				[a-zA-Z0-9_\-/]{1,}\.[a-z]{1,4}
				(?:[\?|/][^"|']{0,}|))
				|
				([a-zA-Z0-9_\-]{1,}
				\.(?:php|asp|aspx|jsp)
				(?:\?[^"|']{0,}|))
			)
			(?:"|')%s)
		""" % ("",""), re.VERBOSE)
		self.__max_connections = threads

	#### First helper functions
	def __add_endpoints(self, endpoints_list):
		# Just to avoid the repeat of converting list to set for removing dups and so on
		for endpoint in endpoints_list:
			if endpoint.startswith("/"):
				endpoint = endpoint[1:]
			if endpoint.endswith("/"):
				enpoint = endpoint[:-1]
			self.endpoints.add(endpoint)
		self.endpoints = set(sorted(self.endpoints))

	def remove_endpoints(self, end=[], contain=[], matches=[]):
		# Hmm, just to be sure
		old = len(self.endpoints)
		self.endpoints = { e[1:] if e.startswith("/") else e for e in self.endpoints}
		self.endpoints = { e[:-1] if e.endswith("/") else e for e in self.endpoints}
		# Brace yourself I'm gonna use magic :D
		if end or contain or matches:
			if end:
				end = [ e.strip().replace("*","") for e in end]
				self.endpoints = set(filter( lambda x: not x.endswith(tuple(end)), self.endpoints))
			if contain:
				self.endpoints = set([
					e for e in self.endpoints if
					all(s.strip().replace("*","") not in e for s in contain)
				])
			if matches:
				for regex in matches:
					search = re.compile(regex)
					self.endpoints = set([e for e in self.endpoints if not search.match(e)])
			print(f"{color.green}[+] {color.reset}Filtered unwanted endpoints. (Gone from {old} to {len(self.endpoints)})", flush=True)

	def splitter(self):
		old = len(self.endpoints)
		result  = set()
		for path in self.endpoints:
			result.add(path)
			current = path
			if current.startswith("/"):
				current = current[1:]
			while current:
				s       = os.path.split(current)
				current = s[0]
				for sub in s:
					if sub.startswith("/"):
						sub = sub[1:]
					if sub!="":
						result.add(sub)
		self.endpoints = set(sorted(result))
		print(f"{color.green} [+] {color.reset}Generated new endpoints with recursion, increased from {old} to {len(self.endpoints)}", flush=True)

	def cleaner(self, url):
		for parameter in list(parse.parse_qs(parse.urlparse(url).query).keys()):
			self.parameters.add(parameter)
		path    = parse.urlparse(url).path.replace("//","/").split("?")[0]
		return path

	### Now let's get to work
	def get_urls_from_waybackarchive(self,endswith="", search_subdomains=False):
		if search_subdomains:
			count_url = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&showNumPages=true"
			page_url  = f"https://web.archive.org/cdx/search/cdx?url=*.{self.domain}/*&filter=statuscode:200&output=json&fl=original&collapse=urlkey&page="
		else:
			count_url = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&showNumPages=true"
			page_url  = f"https://web.archive.org/cdx/search/cdx?url={self.domain}/*&filter=statuscode:200&output=json&fl=original&collapse=urlkey&page="
		def scrape( wanted_urls, url, end):
			try:
				session = requests.session()
				data    = session.get(url, headers=self.__headers, timeout=20, verify=False).json()
				if data:
					urls = set([ x[0] for x in data[1:]])
					for u in urls:
						# My funny workaround for fixing shitty results lol
						u = u.split("?")[0].strip().replace("://",":blah~rrr~blah:").replace("//","/").replace(":blah~rrr~blah:","://").replace("\/","/") # Mainly to get the real js files
						fu = u.strip().replace("://",":blah~rrr~blah:").replace("//","/").replace(":blah~rrr~blah:","://").replace("\/","/") # To extract parameters later
						if u not in self.wayback_urls:
							self.wayback_urls.append(u)
						if end:
							if u.endswith(end) and u not in wanted_urls:
								wanted_urls.append(fu)
						else:
							if u not in wanted_urls:
								wanted_urls.append(fu)
					if end:
						sys.stdout.write("\r | "+f"Collected a total of {len(self.wayback_urls)} valid unique urls, and {len(wanted_urls)} (*{endswith}) file(s). (Real-time filtering)   ")
						sys.stdout.flush()
					else:
						sys.stdout.write("\r | "+f"Collected a total of {len(self.wayback_urls)} valid unique urls. (Real-time filtering)   ")
						sys.stdout.flush()
				session.close()

			except Exception as e:
				# print(e)
				# print(url) # some pages from web archive would be empty so it would give json error
				pass

		wanted_urls = []
		try:
			count = int(requests.get(count_url).text)
			sys.stdout.write(f" | Querying wayback machine for urls in concurrent...\n")
			sys.stdout.flush()
			with concurrent.futures.ThreadPoolExecutor(max_workers=self.__max_connections) as executor:
				futures = []
				start = time.time()
				if endswith:
					sys.stdout.write("\r | "+f"Collected a total of {len(self.wayback_urls)} valid unique urls, and {len(wanted_urls)} (*{endswith}) file(s). (Real-time filtering)   ")
					sys.stdout.flush()
				else:
					sys.stdout.write("\r | "+f"Collected a total of {len(self.wayback_urls)} valid unique urls. (Real-time filtering)   ")
					sys.stdout.flush()

				for page in range(count):
					futures.append( executor.submit(scrape, wanted_urls, page_url+str(page), endswith) )
					time.sleep(0.5)

				for cdx_search in concurrent.futures.as_completed(futures):
					pass
				del futures[:]

			sys.stdout.write(f"\n{color.blue} |{color.reset} Wayback Elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n")
			sys.stdout.flush()
		except Exception as e:
			print(e)
			pass
		return wanted_urls

	def collect_js_files(self, search_subdomains=False):
		sys.stdout.write(f"{color.green}[+]{color.reset} Collecting js files..\n")
		sys.stdout.flush()
		start = time.time()
		while True:
			collected = []
			sys.stdout.write("\r | "+"Collected a total of 0 valid unique js files using parser.")
			sys.stdout.flush()
			try:
				data = requests.get(f"{self.scheme}://{self.domain}", headers=self.__headers, timeout=10).text
				soup = bs(data,'html.parser')
				script_tags = soup.findAll("script", {"type" : "text/javascript"})
				for tag in script_tags:
					sys.stdout.write("\r | "+f"Collected a total of {len(collected)} valid unique js files using parser.")
					sys.stdout.flush()
					try:
						url = tag["src"]
						uu  = parse.urlparse(url)
						if url.startswith("/"):
							url = f"{self.scheme}://{self.domain}"+uu.path
						else:
							url = uu.scheme+"://"+uu.netloc.split(":")[0].split("/")[0]+uu.path

						if url not in collected:
							collected.append(url)#+uu.params)
					except:
						pass
				break
			except Exception as e:
				# print(e)
				pass
		sys.stdout.write(f"\n{color.blue} |{color.reset} Parser Elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n | \n")
		sys.stdout.flush()
		collected.extend(self.get_urls_from_waybackarchive(endswith=".js", search_subdomains=search_subdomains))
		collected = sorted(set(collected))
		worth_read = []
		for js in collected:
			not_lib = False
			for keyword in [".min.", "jquery", "bootstrap", "tether", "popper", "backbone", "vue", "react", "ember", "angular", "polymer", "ext"]:
				if keyword in js.lower():
					break
			else:
				# If no keyword is found in this js files,
				not_lib = True

			if not_lib:
				worth_read.append(js)

		sys.stdout.write(f"{color.cyan} |{color.green} Total collected: {len(collected)} js files! (Possible {len(worth_read)} written by them){color.reset}\n\n")
		self.js_files = collected
		return {"all":collected, "worth_read":worth_read}

	def collect_endpoints_from_js_files(self, js_urls=[]):
		total_endpoints = list()
		def grabber(js_file):
			result = {"file":js_file, "endpoints":set()}
			try:
				req = requests.get(js_file, verify=False, timeout=30)
				js  = req.text.replace("\/","/")
			except requests.exceptions.RequestException:
				return result
			except Exception as e:
				print(e, flush=True)
				return result
			else:
				endpoints = self.endpoint_regex.findall(js)
				if endpoints:
					endpoints = [e[1] for e in endpoints]
					for endpoint in endpoints:
						if endpoint:
							result['endpoints'].add(endpoint)
			return result
		###################################
		if not js_urls:
			js_urls = self.js_files
		if js_urls:
			sys.stdout.write(f"{color.green}[+]{color.reset} Collecting endpoints from {len(js_urls)} js file(s)...\n")
			sys.stdout.flush()
			with concurrent.futures.ThreadPoolExecutor(max_workers=(self.__max_connections) ) as executor:
				futures = []
				start   = time.time()
				for js_url in js_urls:
					sys.stdout.write("\r | Parsing js files in concurrent...")
					sys.stdout.flush()
					futures.append(executor.submit(grabber, js_url))
				sys.stdout.write("\r | Collected 0 endpoint(s) from js files...")
				sys.stdout.flush()
				try:
					for check in concurrent.futures.as_completed(futures):
						result = check.result()
						if result and result['endpoints']:
							for endpoint in result['endpoints']:
								total_endpoints.append(self.cleaner(endpoint))
						total_endpoints = sorted(set(total_endpoints))
						sys.stdout.write("\r | Collected {} endpoint(s) from js files...".format(len(total_endpoints)))
						sys.stdout.flush()
				except Exception as e:
					print(e, flush=True)
					pass
				finally:
					del futures[:]

			sys.stdout.write(f"\n{color.blue} |{color.reset} Elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n | \n")
			sys.stdout.flush()
			self.__add_endpoints(total_endpoints)

	def wayback_endpoints(self):
		total_endpoints = []
		if self.wayback_urls:
			sys.stdout.write(f"{color.green}[+]{color.reset} Collecting endpoints from collected wayback url(s)...\n")
			sys.stdout.flush()
			start = time.time()
			# Figured out that sequential parsing in this CPU-Bound function is faster 1.5x than concurrent processs pool
			sys.stdout.write("\r | Sequential parsing...")
			sys.stdout.flush()
			number = 0
			for wayback_url in self.wayback_urls:
				number +=1
				total_endpoints.append(self.cleaner(wayback_url))
				total_endpoints = sorted(set(total_endpoints))
				sys.stdout.write("\r | Found {} endpoint(s) (Total progress:{}/{})".format( len(total_endpoints),number,len(self.wayback_urls)) )
				sys.stdout.flush()
			sys.stdout.write(f"\n{color.blue} |{color.reset} Elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n |\n")
			sys.stdout.flush()
		self.__add_endpoints(total_endpoints)

	def commoncrawl_endpoints(self, search_subdomains=False):
		def scrape(wanted_urls, url):
			try:
				session = requests.session()
				data = session.get(url, headers=self.__headers, timeout=20).text
				if data:
					urls = set(data.splitlines())
					for u in urls:
						# My funny workaround for fixing shitty results lol
						u = u.replace("://",":blah~rrr~blah:").replace("//","/").replace(":blah~rrr~blah:","://").replace("\/","/")
						wanted_urls.add(u)
					sys.stdout.write("\r | "+f"Collected a total of {len(urls)} valid unique urls. (Real-time filtering)   ")
					sys.stdout.flush()
				session.close()

			except Exception as e:
				# print(e)
				pass

		wanted_urls,total_endpoints = set(),[]
		try:
			# Dynamically allocating cdx indexes
			while True:
				try:
					cdx_json = requests.get("http://index.commoncrawl.org/collinfo.json").json()
					cdx_urls = [cdx['cdx-api'] for cdx in cdx_json]
					if search_subdomains:
						domain_part = f"?url=*.{self.domain}/*&fl=url&filter==status:200"#&output=json"
					else:
						domain_part = f"?url={self.domain}/*&fl=url&filter==status:200"#&output=json"
					break
				except:
					continue
			sys.stdout.write(f"{color.green}[+]{color.reset} Querying commoncrawl cdx for urls in concurrent...\n")
			sys.stdout.flush()
			with concurrent.futures.ThreadPoolExecutor(max_workers=self.__max_connections ) as executor:
				futures = []
				sys.stdout.write("\r | "+f"Collected a total of {len(wanted_urls)} valid unique urls. (Real-time filtering)    ")
				sys.stdout.flush()
				start = time.time()
				for cdx_part in cdx_urls:
					url = cdx_part + domain_part
					futures.append( executor.submit(scrape, wanted_urls, url) )
					time.sleep(0.5)

				for cdx_index in concurrent.futures.as_completed(futures):
					pass
			sys.stdout.write("\r | "+f"Collected a total of {len(wanted_urls)} valid unique urls. (Real-time filtering)    ")
			sys.stdout.flush()
			del futures[:]

		except Exception as e:
			# print(e)
			# traceback.print_exc()
			pass
		else:
			# Now let's collect endpoints, code copied from above ofc
			sys.stdout.write(f"\n{color.green} | {color.reset}Collecting endpoints from collected commoncrawl url(s)...\n")
			sys.stdout.flush()
			sys.stdout.write("\r | Sequential parsing...")
			sys.stdout.flush()
			number = 0
			for commoncrawl_url in wanted_urls:
				number +=1
				total_endpoints.append(self.cleaner(commoncrawl_url))
				total_endpoints = sorted(set(total_endpoints))
				sys.stdout.write("\r | Found {} endpoint(s) (Total progress:{}/{})".format( len(total_endpoints),number,len(wanted_urls)) )
				sys.stdout.flush()

			sys.stdout.write(f"\n{color.blue} |{color.reset} Total elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n |\n")
			sys.stdout.flush()
			self.__add_endpoints(total_endpoints)

	def alienvault_endpoints(self):
		url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{self.domain}/url_list?limit=200&page="
		sys.stdout.write(f"{color.green}[+]{color.reset} Collecting endpoints from Alienvault OTX url(s)...\n")
		sys.stdout.flush()
		total_endpoints = []
		start = time.time()
		for page in range(10000):
			try:
				req  = requests.get(url+str(page), headers=self.__headers)
				json = req.json()
				if json["url_list"]:
					for domain in json["url_list"]:
						total_endpoints.append(self.cleaner(domain["url"]))
				total_endpoints = sorted(set(total_endpoints))
				sys.stdout.write("\r | Found {} endpoint(s).".format(len(total_endpoints)))
				sys.stdout.flush()
				if not json["has_next"]:
					break
			except requests.exceptions.RequestException:
				break
			except Exception as e:
				print(e, flush=True)
				break
		sys.stdout.write(f"\n{color.blue} |{color.reset} Elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n |\n")
		sys.stdout.flush()
		self.__add_endpoints(total_endpoints)

	def builtwith_relationships(self):
		total_endpoints = []
		def grabber(url):
			result = set()
			try:
				req = requests.get(url, verify=False, timeout=30)
				data  = req.text.replace("\/","/")
			except requests.exceptions.RequestException:
				return result
			except Exception as e:
				print(e, flush=True)
				return result
			else:
				endpoints = self.endpoint_regex.findall(data)
				if endpoints:
					endpoints = [e[1] for e in endpoints]
					for endpoint in endpoints:
						if endpoint:
							result.add(endpoint)
			return result
		##########################
		if api_keys.builtwith:
			print(f"{color.green}[+]{color.reset} Collecting connected website using builtwith api...")
			start = time.time()
			req = requests.get(f"https://api.builtwith.com/rv1/api.json?KEY={api_keys.builtwith}&LOOKUP={self.domain}", headers=self.__headers)
			if req:
				sys.stdout.write("\r | Found {} connected website(s) in the relationship profile!".format(len(self.builtwith_connected_websites)))
				sys.stdout.flush()
				j = req.json()
				for Id in j["Relationships"][0]["Identifiers"]:
					for match in Id["Matches"]:
						d = match.get("Domain","")
						if d:
							self.builtwith_connected_websites.add(d)
							sys.stdout.write("\r | Found {} connected website(s) in the relationship profile!".format(len(self.builtwith_connected_websites)))
							sys.stdout.flush()

			# and we are in business :v
			with concurrent.futures.ThreadPoolExecutor(max_workers=self.__max_connections ) as executor:
				futures = []
				sys.stdout.write("\n | Collecting endpoints from connected websites...")
				sys.stdout.flush()
				for url in self.builtwith_connected_websites:
					futures.append(executor.submit(grabber, "https://"+url))
				sys.stdout.write("\r | Collected 0 endpoint(s) from connected websites...")
				sys.stdout.flush()
				try:
					for check in concurrent.futures.as_completed(futures):
						result = check.result()
						if result:
							for endpoint in result:
								total_endpoints.append(self.cleaner(endpoint))
						total_endpoints = sorted(set(total_endpoints))
						sys.stdout.write("\r | Collected {} endpoint(s) from connected websites...".format(len(total_endpoints)))
						sys.stdout.flush()
				except Exception as e:
					print(e, flush=True)
					pass
				finally:
					del futures[:]

			sys.stdout.write(f"\n{color.blue} |{color.reset} Elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n")
			sys.stdout.flush()
			self.__add_endpoints(total_endpoints)
		else:
			print(f"{color.red} [!] Please set builtwith api key first in {color.underline}api_keys.py{color.red} ( Free account at: https://builtwith.com/signup )")

	def github_endpoints(self, repo_url):
		url = "https://api.github.com/repos/{}/{}/git/trees/master?recursive={}"
		total_endpoints,recursion = set(),0
		if self.recursion:
			recursion = 1
		try:
			parse = repo_url.split("github.com/")[1].split("/")
			user  = parse[0]
			repo  = parse[1]
		except:
			print(color.red+" [!] Invalid github url! Example: https://github.com/google/flax")
		else:
			sys.stdout.write(f"{color.green}[+]{color.reset} Collecting endpoints from Github repo...\n")
			sys.stdout.flush()
			start = time.time()
			req  = requests.get(url.format(user, repo, recursion), verify=False)
			data = req.json()
			for path in data["tree"]:
				total_endpoints.add(path["path"])
				sys.stdout.write("\r | Collected {} endpoint(s) from github...".format(len(total_endpoints)))
				sys.stdout.flush()
			sys.stdout.write(f"\n{color.blue} |{color.reset} Elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n |\n")
			sys.stdout.flush()
			self.__add_endpoints(total_endpoints)

	def juicy_files_endpoints(self):
		sys.stdout.write(f"{color.green}[+]{color.reset} Checking sitemap and robots for endpoints...\n")
		sys.stdout.flush()
		start = time.time()
		# First let's take a look at sitemap
		total_endpoints = []
		try:
			req = requests.get(f"{self.scheme}://{self.domain}/sitemap.xml")
			if req:
				xml = req.text
				# I wrote this simple regex instead of the headache of xml parsers and installing them
				xml_regex = re.compile("<loc>(.*)</loc>")
				urls = xml_regex.findall(xml)
				for url in urls:
					total_endpoints.append(self.cleaner(url))
				sys.stdout.write("\r | Found {} endpoint(s)...".format(len(total_endpoints)))
				sys.stdout.flush()
		except requests.exceptions.RequestException:
			pass
		except Exception as e:
			print(e, flush=True)
		# Now let's check robots file
		try:
			req = requests.get(f"{self.scheme}://{self.domain}/robots.txt")
			if req:
				data = req.text
				# It ain't much but it's honest work :"D
				endpoints = re.compile("/.*/").findall(data)
				endpoints = [e.replace("/*/","") for e in endpoints]
				for endpoint in endpoints:
					total_endpoints.append(self.cleaner(endpoint))
				sys.stdout.write("\r | Found {} endpoint(s)...".format(len(total_endpoints)))
				sys.stdout.flush()
		except requests.exceptions.RequestException:
			pass
		except Exception as e:
			print(e, flush=True)
		# May add more files in the future
		total_endpoints = sorted(set(total_endpoints))
		sys.stdout.write("\r | Found {} endpoint(s)...".format(len(total_endpoints)))
		sys.stdout.flush()
		sys.stdout.write(f"\n{color.blue} |{color.reset} Elapsed time {time.strftime('%M.%Sm', time.gmtime(time.time()-start))}.\n |\n")
		sys.stdout.flush()
		self.__add_endpoints(total_endpoints)

# TODO: recursive merge of endpoints directories
def main_logic(site, args):
	threads = 1000
	if args.threads:
		threads = int(args.threads)
	collect = collector(site, threads, bool(args.recursive))
	print(f"{color.white}\t\t - Maximum concurrent threads:{color.reset}{color.white} {collect._collector__max_connections}{color.reset}\n")
	if collect.domain:
		js_files = collect.collect_js_files(bool(args.subdomains))
		if args.js_libraries:
			collect.collect_endpoints_from_js_files(js_files["all"])
		else:
			collect.collect_endpoints_from_js_files(js_files["worth_read"])

		collect.wayback_endpoints()
		collect.commoncrawl_endpoints(bool(args.subdomains))
		collect.alienvault_endpoints()
		if args.juicy_files:
			collect.juicy_files_endpoints()

		if args.github:
			collect.github_endpoints(args.github)

		if args.connected_websites:
			collect.builtwith_relationships()

		if args.use_filter_model:
			collect.remove_endpoints(filter_model.exclude_endswith, filter_model.exclude_contain, filter_model.remove_regex)
		else:
			collect.remove_endpoints()

		if args.recursive:
			collect.splitter()

		outdir = collect.domain
		if args.o:
			if not os.path.isdir(args.o):
				os.mkdir(args.o)
			outdir = args.o
		else:
			if not os.path.isdir(outdir):
				os.mkdir(outdir)

		with open(os.path.join(outdir,"endpoints.txt"), "w") as f:
			for line in sorted(collect.endpoints):
				f.write(line+"\n")
		if collect.parameters:
			with open(os.path.join(outdir,"parameters.txt"), "w") as f:
				for line in sorted(collect.parameters):
					f.write(line+"\n")
		print(f"{color.blue}[>] Written a total of unique {len(collect.endpoints)} endpoint(s) and {len(collect.parameters)} parameter(s).{color.reset}", flush=True)

if __name__ == '__main__':
	print(f"""{color.green}
	  e88'Y88 Y8b Y8b Y888P 888'Y88 888'Y88
	 d888  'Y  Y8b Y8b Y8P  888 ,'Y 888 ,'Y
	C8888       Y8b Y8b Y   888C8   888C8
	 Y888  ,d    Y8b Y8b    888 "   888 "         {color.red}CWFF By {color.Bold}Karim 'D4Vinci' Shoair{color.red} - {color.magneta}V1.0{color.green}
	  "88,d88     Y8P Y     888     888    {color.blue}{color.Bold} - Creating your (C)ustom (W)ordlist (F)or (F)uzzing -{color.reset}""")
	parser = argparse.ArgumentParser(prog='CWFF')
	parser.add_argument("domain", help="Target website(ofc)")
	parser.add_argument("--threads", help="The number of maximum concurrent threads to use (Default:1000)")
	parser.add_argument("--github", help="Collect endpoints from a given github repo (ex:https://github.com/google/flax)")
	parser.add_argument("--subdomains", help="Extract endpoints from subdomains also while search in the wayback machine!",action="store_true")
	parser.add_argument("--recursive", help="Work on extracted endpoints recursively (Adds more endpoints but less accurate sometimes)!",action="store_true")
	parser.add_argument("--js-libraries", help="Extract endpoints from JS libraries also, not just the JS written by them!",action="store_true")
	parser.add_argument("--connected-websites", help="Include endpoints extracted from connected websites",action="store_true")
	parser.add_argument("--juicy-files", help="Include endpoints extracted from juicy files like sitemap.xml and robots.txt",action="store_true")
	# Using filter model is better because argparse could mess up the regex flag :3
	# parser.add_argument("--exclude-endswith", help="Exclude from the results the endpoints that end with the given strings (separated with comma)")
	# parser.add_argument("--exclude-contain", help="Exclude from the results the endpoints that has the given strings (separated with comma)")
	# parser.add_argument("--remove-regex", help="Remove any endpoint that 'match' this regex.", action='append')
	parser.add_argument("--use-filter-model", help="Filter result endpoints with filter_model file", action='store_true')
	parser.add_argument("-o", help="The output directory for the endpoints and parameters. (Default: website name)")
	args = parser.parse_args()
	main_logic(args.domain, args)
