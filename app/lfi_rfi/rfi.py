import requests 
class RFI:
	def __init__(self,urllinks):
		self.urllinks=urllinks
		self.compromised_rfi=[]
		for url in self.urllinks:
			self.compromised_rfi.append(self.rfi_test(url))
		print(self.compromised_rfi)
	def rfi_test(self,url):
		try:
			with open('app/lfi_rfi/rfi_paths.txt','r') as links:
				for i in links:
					#Because while reading lines from a file python adds "\n" to it and that goes to URL which was
					#causing url encoding of "%A" (I believe so) to migigate this I simply striped the "\n" from
					#the end
					#Checking if the url contains the page query because I was going to add mine here.
					if url.__contains__('?page'):
						url=(str(url.split('?page')[0]+i))
					else:
						url=(str(url+i).rstrip('\n'))
					#This allow_redirects doesn't allow URL to go to base url or any other url 

					req=requests.get(url,allow_redirects=False)
					if req.status_code==200 and str(req.url)==url:
						return("Found RFI "+url)
					elif req.status_code==302 and req.is_permanent_redirect==False:
						print("Temporary Redirected but take a look")
					else:
						print("Not Found"+url)
		except Exception as ex:
			print(ex)

