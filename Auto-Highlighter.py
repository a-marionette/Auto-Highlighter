from burp import IBurpExtender
from burp import IHttpListener
from burp import IContextMenuFactory
from burp import ITab
from java.awt.event import ActionListener
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JComboBox
from javax.swing import Box
from javax.swing import JMenu
from javax.swing import JMenuItem
import sys
import re
import zlib

# Burp looks for a class called BurpExtender to instantiate (with no constructor parameters) and then calls registerExtenderCallbacks() on this object passing in a "callbacks" object.

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, ITab):

    # Implement IBurpExtender

    def registerExtenderCallbacks(self, callbacks):
        # Keep a reference to our callbacks object

        self._callbacks = callbacks

        # Obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # Connect standard out/err to callback to Burp standard out buffer

        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()

        # Set our extension name
        callbacks.setExtensionName("Auto-Highlighter")

        # Register proxy listener to intercept proxy requests
        callbacks.registerHttpListener(self)

        # Registers ContextMenu Factory
        callbacks.registerContextMenuFactory(self)

        self.combocolors = ["red","green","blue","orange","yellow","pink","gray","magenta","cyan"]

        self.colors = {"Scanner":"red","Intruder":"blue","Manual":"Orange","Both Tools":"green"}

        # Add suite tab

        callbacks.addSuiteTab(self)

        self.toolMapping = {callbacks.TOOL_INTRUDER:"Intruder",callbacks.TOOL_SCANNER:"Scanner",callbacks.TOOL_EXTENDER:"Scanner",None:"Manual"}

        self.tools = [callbacks.TOOL_INTRUDER,callbacks.TOOL_SCANNER,callbacks.TOOL_EXTENDER]

        self.keys = {}
        
        print('Extension loaded')

    def getTabCaption(self):

        return "Auto-Highlighter"
    
    def getUiComponent(self):
        
        panel = JPanel()

        # Create layout structure

        boxVertical = Box.createVerticalBox()
        boxHorizontal = Box.createHorizontalBox()
        boxHorizontal1 = Box.createHorizontalBox()
        boxHorizontal2 = Box.createHorizontalBox()
        boxHorizontal3 = Box.createHorizontalBox()
        boxHorizontal4 = Box.createHorizontalBox()

        # Create main UI elements

        jlabel = JLabel("<html><h1>Auto-Highlighter Settings</h1><br><br></html>")
        jlabel1 = JLabel("<html><p>Scanner Highlight Color</html>")
        jlabel2 = JLabel("<html><p>Intruder Highlight Color</html>")
        jlabel3 = JLabel("<html><p>Manual Highlight Color</html>")
        jlabel4 = JLabel("<html><p>Both Tools Highlight Color</html>")

        combo = JComboDropDown("Scanner",self).combobox
        combo2 = JComboDropDown("Intruder",self).combobox
        combo3 = JComboDropDown("Manual",self).combobox
        combo4 = JComboDropDown("Both Tools",self).combobox

        # Add vertical box to panel
    
        panel.add(boxVertical)

        boxVertical.add(boxHorizontal)
        boxVertical.add(boxHorizontal1)
        boxVertical.add(boxHorizontal2)
        boxVertical.add(boxHorizontal3)
        boxVertical.add(boxHorizontal4)

        # Add horizontal boxes to vertical box
        
        boxHorizontal.add(jlabel)
        boxHorizontal1.add(jlabel1)
        boxHorizontal1.add(combo)
        boxHorizontal2.add(jlabel2)
        boxHorizontal2.add(combo2)
        boxHorizontal3.add(jlabel3)
        boxHorizontal3.add(combo3)
        boxHorizontal4.add(jlabel4)
        boxHorizontal4.add(combo4)

        return panel

    def keyExists(self,baseRequestResponse):

        requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
        # Errors for Timed-Out requests in proxy history
        if not requestInfo.getUrl():
            return None, ""
        url = requestInfo.getUrl().toString()
        url = self.cleanURL(url)
        parameters = requestInfo.getParameters()
        parameters = list(filter(lambda x: (x.getType() != x.PARAM_COOKIE), parameters))
        parameterNames = [x.getName().encode('utf-8').strip() for x in parameters]
        parameterNamesString = "".join(parameterNames)
        key = zlib.crc32(url + parameterNamesString)
 
        if key in self.keys:
            return True, key
        else:
            return False, key

    def doHighlight(self,baseRequestResponse,key,keyExist,toolFlag,mode=True):

            history = self._callbacks.getProxyHistory()
            toolMap = self.toolMapping.get(toolFlag)
            color = self.colors[toolMap]
            skipHighlight = False

            if mode:
                # ADD: Figure out existing key values to determine highlight color and update key
                if keyExist:
                    # Find what tool flags the key has
                    keyTools = self.keys.get(key)
                    # If current toolFlag is not in the list, append it to the list
                    if toolFlag not in keyTools: 
                        self.keys[key].append(toolFlag)
                        keyTools = self.keys.get(key)
                    # Check if all toolFlags now exist for the key and if TRUE update highlight color
                    if all(x in keyTools for x in [self._callbacks.TOOL_EXTENDER,self._callbacks.TOOL_INTRUDER]) or all(x in keyTools for x in [self._callbacks.TOOL_SCANNER,self._callbacks.TOOL_INTRUDER]):
                        color = self.colors.get("Both Tools")
                    else:
                        skipHighlight = True
                # Create new key
                else:
                    self.keys[key] = [toolFlag]
            # REMOVE: Set highlight to None and remove key 
            else:
                color = None
                self.keys.pop(key,None)

            # Iterate through Proxy History to apply or clear highlight
            if not skipHighlight:
                for baseRequestResponse in history:
                    keyExistProxy, keyProxy = self.keyExists(baseRequestResponse)
                    if not keyExistProxy:
                        print("Hit error, no URL for request")
                        continue
                    if key == keyProxy:
                        baseRequestResponse.setHighlight(color)

    def createMenuItems(self,invocation):

        items = []
        contexts = [invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,invocation.CONTEXT_PROXY_HISTORY
,invocation.CONTEXT_TARGET_SITE_MAP_TABLE,invocation.CONTEXT_TARGET_SITE_MAP_TREE]

        if invocation.getInvocationContext() in contexts:
            baseRequestResponse = invocation.getSelectedMessages()[0]
            self.keyExists(baseRequestResponse)
            parentMenu = HighlighterParentMenu().menu
            keyExist, key = self.keyExists(baseRequestResponse)
            if keyExist:
                parentMenu.add(HighlighterRemoveKeyedMenuItem(lambda: self.doHighlight(baseRequestResponse,key,keyExist,None,False)).menuitem)
            else:
                parentMenu.add(HighlighterAddKeyedMenuItem(lambda: self.doHighlight(baseRequestResponse,key,keyExist,None,True)).menuitem)  
            items.append(parentMenu)
            return items
        else:
            pass

    def processHttpMessage(self,toolFlag,messageIsRequest,messageInfo):



        # If tool origin is Intruder,Scanner,or Extender -> Send to ProxyHistoryHighlight function for further processing

        

        if not messageIsRequest:
            return

        if toolFlag not in self.tools:
            return

        keyExist, key = self.keyExists(messageInfo)

        self.doHighlight(messageInfo,key,keyExist,toolFlag,True)

    def cleanURL(self,url):

        # GUID (Optional Dash), Hashes, Any purely numeric sequence

        regexs = ["{?\w{8}-?\w{4}-?\w{4}-?\w{4}-?\w{12}}?","^[a-fA-F0-9]{32}$","^[a-fA-F0-9]{40}$","^[a-fA-F0-9]{56}$","^[a-fA-F0-9]{64}$","^[a-fA-F0-9]{96}$","^[a-fA-F0-9]{128}$","^\d+$"]
        temp = '(?:% s)' % '|'.join(regexs)
        url = str(url).split("/")
        indexes = []

        for i, elm in enumerate(url):
            if re.match(temp, elm):
                indexes.append(i)

        for index in sorted(indexes, reverse=True):
            url[index] = "<id>"

        url = "/".join(url).rstrip("/")

        return url

class HighlighterParentMenu(ActionListener):
    """
    HighlighterParentMenu creates a new top-level context menu.
    """

    def __init__(self):

        self.menu = JMenu("Auto-Highlighter")

class HighlighterAddKeyedMenuItem(ActionListener):
    """
    HighlighterAddKeyedMenuItem creates a new submenu.
    """

    def __init__(self, action, text="Add Highlight From Keyed Parameters"):

        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(True)
        self.menuitem.addActionListener(self)
        self.action = action

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:
        """

        self.action()
   

class HighlighterRemoveKeyedMenuItem(ActionListener):
    """
    HighlighterRemoveKeyedMenuItem creates a new sub menu.
    """

    def __init__(self, action, text="Remove Highlight From Keyed Parameters"):

        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(True)
        self.menuitem.addActionListener(self)
        self.action = action

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:
        """

        self.action()

class JComboDropDown(ActionListener):
    """
    JComboDropDown creates a new dropdown.
    """

    def __init__(self,tool,extender):

        self.extender = extender
        self.combobox = JComboBox(self.extender.combocolors)
        self.combobox.addActionListener(self)
        self.tool = tool

        # Create combox box color based on saved value or default

        setting = self.extender._callbacks.loadExtensionSetting(self.tool)
        if setting:
            self.combobox.setSelectedItem(setting)
            self.extender.colors[self.tool] = setting
        else:
            self.combobox.setSelectedItem(self.extender.colors.get(self.tool))

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:

        """

        selected = self.combobox.getSelectedItem()
        self.extender._callbacks.saveExtensionSetting(self.tool,selected)
        self.extender.colors[self.tool] = selected
