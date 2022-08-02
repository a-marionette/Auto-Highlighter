# Auto-Highlighter

### What is it?

* Auto-Highlighter is a Burp Extension that helps you track your progress on an assessment
* **How it works:**
	* You right-click a request in "Proxy History" and apply a highlight using the extension's context menu
	* All requests "matching" the highlighted one (past and future) will be highlighted

### How to use it?

* Ensure Burp Suite is configured to use Jython
* Ensure Burp Suite loaded exceptions_fix.py is loaded from a Modules directory you define (Project Options)

![](example.gif)

### Features

* Quickly identify requests you've previously triaged -- On to the next one!
* Two modes of operation (Available in context menus after right-clicking a request in Proxy History)
	* **Tag-Based higlight mode** - Select in Burp Tab _(Configure in extension settings tab)_
	* **Explicit highlight mode** - Select a color from the dropdown menu
* Determines unique requests based off the HTTP Method, URL, and parameters
	* Automatically normalizes URLs with route parameters such as IDs or GUIDs
* Configure custom highlight colors for tag-based higlighting

### Note

* The extension will not work if your application generates dynamic parameter names (e.g. - ctl100)

### About

* amarionette _(Michael Maturi)_ Security Researcher

### Thanks to

https://github.com/securityMB for exceptions_fix.py
