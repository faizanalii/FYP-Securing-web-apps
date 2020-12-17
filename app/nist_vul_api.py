import requests
class VulFind:
	def __init__(self,data):
		self.data=data
		self.info=[]		
		for i in self.data:
			#Data fifth var is version and last is Technology used. 
			if i[len(i)-1]!='Not Found' and i[len(i)-2]!='Not Found':
				response=requests.get('https://services.nvd.nist.gov/rest/json/cves/1.0?keyword={} {}&addOns=dictionaryCpes'.format(i[len(i)-1],i[len(i)-2]))
				# response=requests.get('https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=nginx 1.4&addOns=dictionaryCpes')
				print(response.url)
				if response.status_code==200:
					data_req=response.json()
					if data_req['totalResults']>0:
						print(self.collectvul(data_req))
					else:
						print('Nothing Available in DB regarding this')
				else:
					print("Status Not Active")
			else:
				continue
	def collectvul(self,data_req):
		data_req=data_req
		items_db=[]
		for i in data_req['result']['CVE_Items']:
			if i['impact']['baseMetricV2']['severity']=='HIGH' or 'MEDIUM':
				items_db.append(i['cve']['CVE_data_meta']['ID'])
				items_db.append(i['impact']['baseMetricV2']['severity'])
				items_db.append(i['impact']['baseMetricV2']['impactScore'])
				for j in i['cve']['description']['description_data']:
					items_db.append(j['value'])
				#I'm not adding reference URL's here because they're dynamic(Some has one ref link and some has 10,12)
				#and creating issues in the code
				# for j in i['cve']['references']['reference_data']:
				# 	items_db.append(j['url'])
			else:
				print("Severity was low so I let that GO")
		return self.managingdata(items_db)
	def managingdata(self,items_db):
		items_db=items_db
		t=0
		complete_db=[]
		for i in range(int(len(items_db)/4)):
			complete_db.append(items_db[t:t+4])
			t+=4
		return complete_db

