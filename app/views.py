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
from django.template.loader import get_template
from xhtml2pdf import pisa
# Create your views here.
def index(request):
	return render(request,'index.html')
report_sql_os_results=[]
report_all_links=[]
report_broken_list=[]
report_sec_headers=[]
report_data=[]
report_os_names=[]
report_xss_found=[]
report_lfi_results=[]
report_rfi_results=[]
def urlstatus(request):
	start=time.time()
	form=forms.urlform()
	if request.method=='POST':
		form=forms.urlform(request.POST)
		if form.is_valid():
			link=form['urlfield'].value()
			print(link)
			try:
				print("Started SQL OS")
				sql_os_test=Test_Injection(link)
				sql_os_results=sql_os_test.result_injections
				#Added Report Variable for SQL OS
				global report_sql_os_results
				report_sql_os_results=sql_os_results
			except Exception as ex:
				print(ex)
			#Send inputed link to Links class from extractinglinks module to extract all the external and internal links of web
			print("Started CAWLING LINKS")
			crawl_web=extractinglinks.Links(link)
			#extracting links returns list of internal and external links 
			all_links=crawl_web.all_links
			#Added Report List for all links
			global report_all_links
			report_all_links=all_links
			#Sending all gathered links to broken_links to test either any links are broken or not 
			print("Started Broken Links")
			broked=broken_links.BrokenLinks(all_links[1])
			#Checking either there are any broken links or not
			broken_list=[]
			if len(broked.links_broke)>0:
				broken_list=broked.links_broke
				#Adding Report Broken List List
				global report_broken_list
				report_broken_list=broken_list
			else:
				print('No Broken Links Found')
			if statuscheck(link)==True:
				#Checking Header for info like X-XSS-Protection, X-Content... etc
				header_web=header_security.HeaderCheck(link)
				# print(collectinfo(link))
				#Headers Configuration 
				#Adding Report Security Headers
				global report_sec_headers
				if header_web.headercheck==None:
					sec_headers='Headers are Configured correctly'
					report_sec_headers=sec_headers
				else:
					sec_headers=header_web.headercheck
					report_sec_headers=sec_headers
				#collecting data about website like ports info, version detection etc
				# data=collectinfo(link)
				#Sending Link to collectInfo Class to Collect Info about the backend
				print("Started Collecting Info")
				data=Info(domain(link))
				#Setting the data because I've set a var os name datainfo 
				data=data.datainfo
				#Adding Report Data
				global report_data
				report_data=data
				#Sending Collected info to nist api 'https://services.nvd.nist.gov/rest/json/cves/1.0'
				print("Started Nist API")
				oops=nist_vul_api.VulFind(data)
				##OS Detection Phase 
				print("started OS Detection")
				os=OS_Detection(domain(link))
				os_names=os.os_name
				print(os_names)
				#Adding Report OS Names
				global report_os_names
				report_os_names=os_names
				##XSS Testing, Sending all Internal links to xssTest class because External doesn't they're not our headache
				#Adding the main internal link 
				print("Started XSS Detection")
				xss=xssTest(all_links[0],link)
				xss_found=xss.allDetails
				print(xss_found)
				global report_xss_found
				report_xss_found=xss_found
				print("Started LFI RFI")
				lfi=LFI(all_links[0])
				rfi=RFI(all_links[0])
				lfi_results=lfi.compromised_lfi
				rfi_results=rfi.compromised_rfi
				#Adding Report LFI, RFI
				global report_rfi_results,report_lfi_results
				report_rfi_results,report_lfi_results=rfi_results,lfi_results
				print("Total Time=",time.time()-start)
				try:
					return render(request,'info.html',{'data':data,'Internal':all_links[0],'External':all_links[1]
						,'broken_list':broken_list,'os_names':os_names,'sec_headers':sec_headers,'xss_found':xss_found
						,'sql_os_results':sql_os_results,'lfi_results':lfi_results,'rfi_results':rfi_results})
				except:
					return render(request,'info.html',{'data':data,'Internal':all_links[0],'External':all_links[1]
						,'broken_list':broken_list,'os_names':os_names,'sec_headers':sec_headers,'xss_found':xss_found,
						'lfi_results':lfi_results,'rfi_results':rfi_results})
			else:
				print("Website is Down")
		else:
			print("Invalid Link")
	return render(request,'main.html',{'form':form})
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

def render_pdf_view(request):
    template_path = 'pdfreport.html'
    print(report_all_links)
    try:
    	context = {'data': report_data,'Internal':report_all_links[0],'External':report_all_links[1],'broken_links':report_broken_list
    	,'os_names':report_os_names,'sec_headers':report_sec_headers,'xss_found':report_xss_found,
    	'sql_os_results':report_sql_os_results,'lfi_results':report_lfi_results,'rfi_results':report_rfi_results}
    except:
    	context = {'data': report_data,'Internal':report_all_links[0],'External':report_all_links[1],'broken_links':report_broken_list
    	,'os_names':report_os_names,'sec_headers':report_sec_headers,'xss_found':report_xss_found
    	,'lfi_results':report_lfi_results,'rfi_results':report_rfi_results}
    	# Create a Django response object, and specify content_type as pdf
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'attachment; filename="report.pdf"'
    # find the template and render it.
    template = get_template(template_path)
    html = template.render(context)

    # create a pdf
    pisa_status = pisa.CreatePDF(
       html, dest=response)
    # if error then show some funy view
    if pisa_status.err:
       return HttpResponse('We had some errors <pre>' + html + '</pre>')
    return response
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