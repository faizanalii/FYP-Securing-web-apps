import requests
from pprint import pprint
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

#XSS CODE 
class xssTest:
	def __init__(self,url_list,main_url):
		print(url_list)
		url_list.append(main_url)
		print(url_list)
		self.allDetails=[]
		if url_list is not None:		
			for i in url_list:
				self.allDetails.append(self.scan_xss(i))
				print(i)
		else:
			print("IT WAS EMPTY DUDE!")
		# print(self.allDetails)
	def get_all_forms(self,url):
		#Gets a URL and returns all the forms
		soup = bs(requests.get(url).content, "html.parser")
		return soup.find_all("form")
	#Gets Form Information like form inputs blah blah 
	def get_form_details(self,form):
		try:	
			if len(form)>0:
				details = {}
				action = form.attrs.get("action").lower()
				method = form.attrs.get("method", "get").lower()
				inputs = []
				for input_tag in form.find_all("input"):
					input_type = input_tag.attrs.get("type", "text")
					input_name = input_tag.attrs.get("name")
					inputs.append({"type": input_type, "name": input_name})
				details["action"] = action
				details["method"] = method
				details["inputs"] = inputs
				return details
		except Exception as ex:
			print(ex)
	#This function submits the form 
	def submit_form(self,form_details, url, value):
		try:
			target_url = urljoin(url, form_details["action"])
			inputs = form_details["inputs"]
			data = {}
			for input in inputs:
				if input["type"] == "text" or input["type"] == "search":
					input["value"] = value
				input_name = input.get("name")
				input_value = input.get("value")
				if input_name and input_value:
					data[input_name] = input_value
			if form_details["method"] == "post":
				return requests.post(target_url, data=data)
			else:
				return requests.get(target_url, params=data)
		except Exception as ex:
			print(ex)
	def scan_xss(self,url):
		forms = self.get_all_forms(url)
		forms_in_url=f"[+] Detected {len(forms)} forms on {url}."
		# print(forms_in_url)
		js_script = "<Script>alert('hi')</scripT>"
		is_vulnerable = False
		allDetails=[]
		try:		
			if len(forms)>0:	
				for form in forms:
					form_details = self.get_form_details(form)
					content = self.submit_form(form_details, url, js_script).content.decode()
					if js_script in content:
						xss_detected=f"[+] XSS Detected on {url}"
						# print(xss_detected)
						allDetails.append(forms_in_url)
						allDetails.append(xss_detected)
						# print(f"[*] Form details:")
						# print(form_details)
						allDetails.append(form_details)
						is_vulnerable = True
						allDetails.append(is_vulnerable)
				if allDetails is not None:	
					return allDetails
			else:
				print("No Form Detected"+str(url))
		except Exception as ex:
			print(ex)