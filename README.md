# Auto-Highlighter

### What is it?

- Auto-Highlighter is a Burp Extension that helps you track certain types of analysis (Scanner/Intruder) per unique request encountered
- It processes every HTTP request sent by Burp Suite and highlights any request originating from either Scanner or Intruder

### Features

* Determines unique requested based off keyed parameters (Ignores cookies)
	* Automatically normalizes URLs with route parameters such as IDs or GUIDs
* Automated highlighting of unique requests from Scanner / Intruder throughout proxy history
* Manual highlighting of unique request throughout proxy history
* Configure highlight colors
	* Intruder
	* Scanner
	* Both Tools
	* Manual

### Why?

* Intruder and Scanner are some of the most common tools used when performing in-depth analysis. To ensure coverage, my workflow always involves using these two tools. Its a quick way to triage coverage of an application on a per-request basis. If your use a different workflow, you can also manually highlight a request and have it apply to all requests matching in your proxy history.

# Credits

* Request Highlighter Authors (https://portswigger.net/bappstore/11729a617d8d4d3b87c82e34b71885c3)
	* Davide 'TwiceDi' Danelon, BeDefended Srl
* InQL Author (GUI Elements)
	* doyensec 

# About
* a-marionette _(Michael Maturi)_ Security Researcher

