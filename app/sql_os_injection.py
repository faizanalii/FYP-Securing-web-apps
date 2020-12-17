from zapv2 import ZAPv2
import tldextract
class Test_Injection:
	def __init__(self,target):
		self.target=target
		self.result_injections=[]
		self.start_test()
	def start_test(self):
		zap=ZAPv2(proxies={'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'})
		domain=tldextract.extract(self.target).domain
		#session is saved in the drive so to name it and make that easy simply extracting the domain name and making dir with 
		#domain name
		zap.core.new_session(domain)
		zap.core.load_session(domain)
		#deleting all previous alerts that are if any case are in the session
		zap.core.delete_all_alerts()
		zap.urlopen(self.target)
		zap.spider.scan(self.target)
		#Doing active scanning fo the web and using sql_os policy which i have made to only test for sql and os command injections
		zap.ascan.scan(self.target)
		while (int(zap.ascan.status())<100):
			print("Scanning Progess ", zap.ascan.status(),"%")
		#Looping through all the alerts as I only need sql and os injection alerts so to refine them I pass the pluginId
		#and find if any exits (More info 'https://www.zaproxy.org/docs/docker/api-scan/')
		for i in zap.core.alerts():
			if i['pluginId']=='20018' or i['pluginId']=='40018' or i['pluginId']=='40019' or i['pluginId']=='40020' or i['pluginId']=='40021' or i['pluginId']=='40022':
				self.result_injections.append(i)
		print("Scan End")