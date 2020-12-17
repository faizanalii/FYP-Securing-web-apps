from django import forms
class urlform(forms.Form):
	urlfield=forms.URLField(label='Enter URL',required=True)
