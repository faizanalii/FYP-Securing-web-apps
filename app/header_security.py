import requests
class HeaderCheck:
	def __init__(self,target):
		self.target=target
		self.headercheck=self.explore()
		print(self.headercheck)
	def explore(self):
		resp=requests.get(self.target)
		headers=resp.headers
		i='X-XSS-Protection'
		j='X-Frame-Options'
		k='X-Content-Type-Options'
		l=[]
		for t in headers.keys():	
				l.append(t)
		if len(l)>=1:		
			if i and j and k in l:
				return None
			elif i and j in l and k not in l:
				return k
			elif i and k in l and j not in l:
				return j
			elif j and k in l and i not in l:
				return i
			else:
				return (i,j,k)