import nmap3
class Info:
	def __init__(self,link):
		self.link=link
		self.datainfo=self.collectinfo()
	def collectinfo(self):
		nmap=nmap3.Nmap()
		#Calling Domain Fucntion to Refine the Domain
		results=nmap.scan_top_ports(self.link,args='-sV')
		ip=list(results.keys())[0]
		portinfo=[]
		for i in range(len(results[ip])):
			portinfo.append(results[ip][i]['protocol'])
			portinfo.append(results[ip][i]['portid'])
			portinfo.append(results[ip][i]['state'])
			if 'version' and 'name' and 'product' in results[ip][i]['service'].keys():
				portinfo.append(results[ip][i]['service']['name'])
				try:
					portinfo.append(results[ip][i]['service']['version'])
				except:
					portinfo.append('Not Found')
				portinfo.append(results[ip][i]['service']['product'])
			elif 'name' and 'product' in results[ip][i]['service'].keys() and 'version' not in results[ip][i]['service'].keys():
				portinfo.append(results[ip][i]['service']['name'])
				portinfo.append('Not Found')
				portinfo.append(results[ip][i]['service']['product'])
			elif 'name' and 'version' in results[ip][i]['service'].keys() and 'product' not in results[ip][i]['service'].keys():
				portinfo.append(results[ip][i]['service']['name'])
				portinfo.append(results[ip][i]['service']['version'])
				portinfo.append('Not Found')
			elif 'name' in results[ip][i]['service'].keys() and 'product' and 'version' not in results[ip][i]['service'].keys():
				portinfo.append(results[ip][i]['service']['name'])
				portinfo.append('Not Found')
				portinfo.append('Not Found')
			elif 'name' and 'version' and 'product' not in results[ip][i]['service'].keys():
				portinfo.append('Not Found')
				portinfo.append('Not Found')
				portinfo.append('Not Found')
			else:
				print("Ok End Else")				
		print(len(portinfo))
		print(portinfo)
		#here I'm checking either the length of portinfo list is even or odd if it returns somevalue when  taking modulus 
		#I'll adding not found to the list until the list returns none when took modulus by 6
		#I did this to add portinfo list equally to the complete info and render it on the web.
		mod=len(portinfo)%6
		if mod>0 and mod<6:
			while mod!=6:
				portinfo.append('Not Found')
				mod+=1
		print(len(portinfo))
		print(portinfo)
		return self.managingdata(portinfo)
	def managingdata(self,portinfo):
		completeinfo=[]
		t=0
		for i in range(int(len(portinfo)/6)):
			completeinfo.append(portinfo[t:t+6])
			t+=6
		return completeinfo