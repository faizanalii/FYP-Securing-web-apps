#To Test if any links are broken from the website
import requests
import threading
class BrokenLinks:
	#Getting all links from the collected links
	def __init__(self,links):
		self.links=links
		self.links_broke=[]
		#As Collecting two links list(Internal and External [[internal],[external]]) so.. for that 2 loops
		for i in self.links:
			# for j in i:
				#Sending every link to for test
				#PREVIOUS CODE
			self.links_broke.append(self.testlinks(i))
				#Changed Code
				# t=threading.Thread(target=self.testlinks(j))
				# t.start()
	def testlinks(self,link):
		try:
			resp=requests.get(link)
			#Testing if status of any link matches this code if yes then it should be retured
			if resp.status_code in [400,404,403,408,409,501,502,503]:
				#PREVIOUS CODE
				return(link,resp.status_code)
				#Changed Code
				# self.links_broke.append((link,resp.status_code))
		except Exception as ex:
			print(ex)

