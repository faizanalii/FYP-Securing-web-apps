from django.shortcuts import render
from django.http import HttpResponse,HttpResponseRedirect
from app import forms
import nmap3
import tldextract
import urllib.request
from app import extractinglinks 
from app import nist_vul_api
from app import broken_links
from app import header_security
from app.os_detect import OS_Detection
from app.collectingInfo import Info
from app.xss_test import xssTest
from app.lfi_rfi.lfi import LFI
from app.lfi_rfi.rfi import RFI
from app.sql_os_injection import Test_Injection
import time
# Create your views here.
def urlstatus(request):
	start=time.time()
	form=forms.urlform()
	if request.method=='POST':
		form=forms.urlform(request.POST)
		if form.is_valid():
			link=form['urlfield'].value()
			print(link)
			sql_os_test=Test_Injection(link)
			for i in sql_os_test.result_injections:
				print(i)
			#Send inputed link to Links class from extractinglinks module to extract all the external and internal links of web
			crawl_web=extractinglinks.Links(link)
			#extracting links returns list of internal and external links 
			all_links=crawl_web.all_links
			#Sending all gathered links to broken_links to test either any links are broken or not 
			broked=broken_links.BrokenLinks(all_links[1])
			#Checking either there are any broken links or not
			broken_list=[]
			if len(broked.links_broke)>0:
				broken_list=broked.links_broke
			else:
				print('No Broken Links Found')
			if statuscheck(link)==True:
				#Checking Header for info like X-XSS-Protection, X-Content... etc
				header_web=header_security.HeaderCheck(link)
				# print(collectinfo(link))
				#Headers Configuration 
				if header_web.headercheck==None:
					sec_headers='Headers are Configured correctly'
				else:
					sec_headers=header_web.headercheck
				#collecting data about website like ports info, version detection etc
				# data=collectinfo(link)
				#Sending Link to collectInfo Class to Collect Info about the backend
				data=Info(domain(link))
				#Setting the data because I've set a var os name datainfo 
				data=data.datainfo
				#Sending Collected info to nist api 'https://services.nvd.nist.gov/rest/json/cves/1.0'
				oops=nist_vul_api.VulFind(data)
				##OS Detection Phase 
				os=OS_Detection(domain(link))
				os_names=os.os_name
				print(os_names)
				##XSS Testing, Sending all Internal links to xssTest class because External doesn't they're not our headache
				#Adding the main internal link 
				xss=xssTest(all_links[0],link)
				xss_found=xss.allDetails
				print(xss_found)
				lfi=LFI(all_links[0])
				rfi=RFI(all_links[0])
				print("Total Time=",time.time()-start)
				return render(request,'info.html',{'data':data,'Internal':all_links[0],'External':all_links[1]
					,'broken_list':broken_list,'os_names':os_names,'sec_headers':sec_headers,'xss_found':xss_found})
			else:
				print("Website is Down")
		else:
			print("Invalid Link")
	return render(request,'index.html',{'form':form})
def statuscheck(link):
	if urllib.request.urlopen(link).getcode()==200:
		return True
	else:
		return False
def domain(link):
	extdomain=tldextract.extract(link)
	#Here I'm refining the URL from let say these 'http://www.google.com' to these 'google.com' because nmap don't accept
	#links which have ssl or have '/' it only accpets domain name
	if len(extdomain[0]):
		extdomain='.'.join(extdomain[0:len(extdomain)])
	else:
		extdomain='.'.join(extdomain[1:len(extdomain)])
	return extdomain
# def collectinfo(link):
# 	nmap=nmap3.Nmap()
# 	#Calling Domain Fucntion to Refine the Domain
# 	results=nmap.scan_top_ports(domain(link),args='-sV')
# 	ip=list(results.keys())[0]
# 	portinfo=[]
# 	for i in range(len(results[ip])):
# 		portinfo.append(results[ip][i]['protocol'])
# 		portinfo.append(results[ip][i]['portid'])
# 		portinfo.append(results[ip][i]['state'])
# 		if 'version' and 'name' and 'product' in results[ip][i]['service'].keys():
# 			portinfo.append(results[ip][i]['service']['name'])
# 			try:
# 				portinfo.append(results[ip][i]['service']['version'])
# 			except:
# 				portinfo.append('Not Found')
# 			portinfo.append(results[ip][i]['service']['product'])
# 		elif 'name' and 'product' in results[ip][i]['service'].keys() and 'version' not in results[ip][i]['service'].keys():
# 			portinfo.append(results[ip][i]['service']['name'])
# 			portinfo.append('Not Found')
# 			portinfo.append(results[ip][i]['service']['product'])
# 		elif 'name' and 'version' in results[ip][i]['service'].keys() and 'product' not in results[ip][i]['service'].keys():
# 			portinfo.append(results[ip][i]['service']['name'])
# 			portinfo.append(results[ip][i]['service']['version'])
# 			portinfo.append('Not Found')
# 		elif 'name' in results[ip][i]['service'].keys() and 'product' and 'version' not in results[ip][i]['service'].keys():
# 			portinfo.append(results[ip][i]['service']['name'])
# 			portinfo.append('Not Found')
# 			portinfo.append('Not Found')
# 		elif 'name' and 'version' and 'product' not in results[ip][i]['service'].keys():
# 			portinfo.append('Not Found')
# 			portinfo.append('Not Found')
# 			portinfo.append('Not Found')
# 		else:
# 			print("Ok End Else")				
# 	print(len(portinfo))
# 	print(portinfo)
# 	#here I'm checking either the length of portinfo list is even or odd if it returns somevalue when  taking modulus 
# 	#I'll adding not found to the list until the list returns none when took modulus by 6
# 	#I did this to add portinfo list equally to the complete info and render it on the web.
# 	mod=len(portinfo)%6
# 	if mod>0 and mod<6:
# 		while mod!=6:
# 			portinfo.append('Not Found')
# 			mod+=1
# 	print(len(portinfo))
# 	print(portinfo)
# 	return test(portinfo)
# def test(portinfo):
# 	completeinfo=[]
# 	t=0
# 	for i in range(int(len(portinfo)/6)):
# 		completeinfo.append(portinfo[t:t+6])
# 		t+=6
# 	return completeinfo