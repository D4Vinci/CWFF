import filter_model
from cwff import *
try:
	 infile = sys.argv[1]
	 outfile = sys.argv[2]
except:
	print(f"{color.red} [!] Correct usage: python filter.py wordlist.txt output.txt")
	sys.exit(0)
else:
	try:
		with open(infile) as f:
			endpoints = set(f.read().split("\n"))
	except:
		print(f"{color.red} [!] Can't read file!")
		sys.exit(0)
	else:
		try:
			collect = collector("")
			collect.endpoints = endpoints
			collect.remove_endpoints(filter_model.exclude_endswith, filter_model.exclude_contain, filter_model.remove_regex)
		except Exception as e:
			print(f"{color.red} [!] Something went wrong!")
			print(e)
		else:
			with open(outfile, "w") as f:
				for endpoint in sorted(collect.endpoints):
					f.write(endpoint+"\n")
			sys.stdout.write(f"{color.green}[+]{color.reset} Written new endpoints to {outfile}\n")
			sys.stdout.flush()
