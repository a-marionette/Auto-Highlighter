# Auto-Highlighter

### What is it?

- Auto-Highlighter helps you track certain types of analysis (Scanner/Intruder) per unique request encountered
- It processes every HTTP request sent by Burp Suite and highlights any request originating from either Scanner or Intruder


### Features

* Determines unique requested based off keyed parameters (Ignores cookies)
	* Automatically normalizes URLs with route parameters such as IDs or GUIDs
* Automated highlighting of unique requests from Scanner / Intruder throughout proxy history
* Manual higlighting of unique request throughout proxy history
* Configure highlight colors
	* Intruder
	* Scanner
	* Both Tools
	* Manual

# Credits

* Request Highlighter Authors (https://portswigger.net/bappstore/11729a617d8d4d3b87c82e34b71885c3)
	* Davide 'TwiceDi' Danelon, BeDefended Srl
* InQL Author (GUI Elements)
	* doyensec 

