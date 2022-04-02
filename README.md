# Auto-Highlighter

### What is it?

* Auto-Highlighter is a Burp Extension that helps you track your progress on an assessment
* It processes every HTTP request sent by Burp Suite and highlights previously higlighted requests

### How to use it?
* Two modes of operation
	* Default higlight mode - Select in Burp Tab
	* Explicit highlight mode - Select a color from the apporpriate dropdown menu
* Use the context menu to invoke either mode

### Features

* Determines unique requested based off keyed parameters (Ignores cookies)
	* Automatically normalizes URLs with route parameters such as IDs or GUIDs
* Manual highlighting of unique request throughout proxy history
* Configure highlight colors
	* **Note:** Scanner and intruder options in the UI are non-functional artifacts and will be introduced in a future release. Ignore for now.

# About
* a-marionette _(Michael Maturi)_ Security Researcher
