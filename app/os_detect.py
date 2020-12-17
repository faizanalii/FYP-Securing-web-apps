import nmap3
import threading
class OS_Detection:
	def __init__(self,url):
		#Getting the link from views
		self.url=url
		#Calling the Function which does the os Detection, REMEMBER OS detection is brute forced and only those are selected 
		# whose accuracy is above 90%
		# self.os_name=self.detection()
		t=threading.Thread(target=self.detection)
		t.start()
		t.join()
		self.os_name=self.result
	def detection(self):
		nmap=nmap3.Nmap()
		#Calling the os_dection module from nmap 
		detection_phase=nmap.nmap_os_detection(self.url)
		# list to store OS's names
		self.result=[]
		for i in detection_phase:
			if int(i['accuracy'])>=90:
				#Only OS names are added to the list 
				self.result.append(i['name'])
			else:
				continue
		#OS's names are sent back
		return self.result
