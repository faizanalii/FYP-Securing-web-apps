import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import colorama
colorama.init()
GREEN = colorama.Fore.GREEN
GRAY = colorama.Fore.LIGHTBLACK_EX
RESET = colorama.Fore.RESET
internal_urls = set()
external_urls = set()
total_urls_visited = 0
class Links:
	def __init__(self,url):
		self.url=url
		print(self.url)
		self.crawl(self.url)
		print("Total Internal Links:",len(internal_urls))
		print("Total External Links:",len(external_urls))
		print("Total:",len(internal_urls)+len(external_urls))
		self.all_links=[]
		list_internal_urls=list(internal_urls)
		list_external_urls=list(external_urls)
		self.all_links.append(list_internal_urls)
		self.all_links.append(list_external_urls)
	def crawl(self,url,max_urls=50):
		self.url=url
		global total_urls_visited
		total_urls_visited+=1
		links=self.get_all_website_links(self.url)
		for link in links:
			if total_urls_visited>50:
				break
			self.crawl(link,max_urls=max_urls)
	def is_valid(self,url):
		self.url=url
		parsed=urlparse(self.url)
		return bool(parsed.netloc) and bool(parsed.scheme)
	def get_all_website_links(self,url):
		self.url=url
		urls=set()
		domain_name=urlparse(self.url).netloc
		soup=BeautifulSoup(requests.get(self.url).content,"html.parser")
		for a_tag in soup.findAll("a"):
			href=a_tag.attrs.get("href")
			if href=="" or href is None:
				continue
			href=urljoin(self.url,href)
			parsed_href=urlparse(href)
			href=parsed_href.scheme+'://'+parsed_href.netloc+parsed_href.path
			if not self.is_valid(href):
				continue
			if href in internal_urls:
				continue
			if domain_name not in href:
				if href not in external_urls:
					print(f"{GRAY}[!] Exteral Link:{href}{RESET}")
					external_urls.add(href)
				continue
			print(f"{GREEN}[*] Internal Link:{href}{RESET}")
			urls.add(href)
			internal_urls.add(href)
		return urls