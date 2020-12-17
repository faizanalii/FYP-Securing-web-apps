import requests
class LFI:
	def __init__(self,urllist):
		self.urllist=urllist
		self.compromised_lfi=[]
		for url in self.urllist:
			self.compromised_lfi.append(self.lfi_test(url))
		print(self.compromised_lfi)
	def lfi_test(self,url):
		try:
			with open('app/lfi_rfi/lfi_paths.txt','r') as links:
				req0=requests.get(url)
				for i in links:
					#Because while reading lines from a file python adds "\n" to it and that goes to URL which was
					#causing url encoding of "%A" (I believe so) to migigate this I simply striped the "\n" from
					#the end 
					url=(str(url+i).rstrip('\n'))
					#This allow_redirects doesn't allow URL to go to base url or any other url 
					req1=requests.get(url,allow_redirects=False)
					if req1.status_code==200:
						return("Found LFI "+ str(req1.url))
					elif req1.status_code==302 and req1.is_permanent_redirect==False:
						print("Temporary Redirected but take a look")
					else:
						print("Not Found"+str(req1.url))
		except Exception as ex:
			print(ex)