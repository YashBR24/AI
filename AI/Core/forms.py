from django import forms

class PromptForm(forms.Form):
    prompt = forms.CharField(label='Enter your image description', max_length=200)
