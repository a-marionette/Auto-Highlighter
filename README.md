# Auto-Highlighter

### What is it?

* Auto-Highlighter is a Burp Extension that helps you track your progress on an assessment
* It processes every HTTP request sent by or proxied via Burp Suite and highlights previously higlighted requests
* Unique requests are determine using the HTTP method, the URI, and request parameters (Excluding headers)

### How to use it?
* Five context menu options (Available in context menus after right-clicking a request in Proxy History). All options except "Explicit" mode are configured in the Extension tab!
	* **Triaged higlight mode**
	* **Interesting higlight mode**
	* **Finding higlight mode**
	* **Ignore higlight mode**
	* **Explicit highlight mode**
* Ensure Burp Suite is configured to use Jython
* Ensure Burp Suite loaded exceptions_fix.py (included, by ) in a Modules directory you define (Project Options)

![](example.gif)

### Features

* Determines unique requested based off keyed parameters (Ignores cookies)
	* Automatically normalizes URLs with route parameters such as IDs or GUIDs
* Manual highlighting of unique request throughout proxy history
* Configure highlight colors

### Note

* The extension will not work if your application generates dynamic parameter names

### About

* amarionette _(Michael Maturi)_ Security Researcher

### Thanks to

https://github.com/securityMB for exceptions_fix.py
