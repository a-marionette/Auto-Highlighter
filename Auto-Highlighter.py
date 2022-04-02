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
from collections import OrderedDict
import sys
import re
import zlib
import ast

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

        self.combocolors = [
            "red",
            "green",
            "blue",
            "orange",
            "yellow",
            "pink",
            "gray",
            "magenta",
            "cyan",
        ]

        self.colors = {
            "Scanner": "red",
            "Intruder": "blue",
            "Manual": "cyan",
            "Both Tools": "green",
        }

        self.automatedTools = {
            callbacks.TOOL_INTRUDER: "Intruder",
            callbacks.TOOL_SCANNER: "Scanner",
            callbacks.TOOL_EXTENDER: "Scanner",
        }

        self.tools = [
            callbacks.TOOL_INTRUDER,
            callbacks.TOOL_SCANNER,
            callbacks.TOOL_EXTENDER,
            callbacks.TOOL_PROXY,
        ]

        self.proxyLookBackLimit = 25000

        self.contextMenuKeys = FixSizeOrderedDict()

        # Add suite tab (This breaks if not at the end!)

        callbacks.addSuiteTab(self)

        print("Extension loaded")
        print("By Michael Maturi @ Mandiant")

        if self._callbacks.loadExtensionSetting("keys"):
            self.keys = ast.literal_eval(self._callbacks.loadExtensionSetting("keys"))
        else:
            self.keys = {}

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

        combo = JComboDropDown("Scanner", self).combobox
        combo2 = JComboDropDown("Intruder", self).combobox
        combo3 = JComboDropDown("Manual", self).combobox
        combo4 = JComboDropDown("Both Tools", self).combobox

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

    def keyExists(self, baseRequestResponse):

        requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
        
        # Handle timed-out requests which will throw an error

        if not requestInfo.getUrl():
            return None, ""

        # Get URL and clean it

        url = requestInfo.getUrl().toString()
        url = self.cleanURL(url)

        # Get parameters that are NOT cookies and clean them

        parameters = requestInfo.getParameters()
        parameters = list(filter(lambda x: (x.getType() != x.PARAM_COOKIE), parameters))
        parameterNames = [x.getName().encode("utf-8").strip() for x in parameters]
        parameterNamesString = "".join(parameterNames)

        # Create a unique identifier using CRC32

        key = zlib.crc32(url + parameterNamesString)

        # Check if the key exists in our keystore
   
        if key in self.keys:
            return True, key
        else:
            return False, key

    def removeHiglight(self,key):
        history = self._callbacks.getProxyHistory()
        for baseRequestResponse in history[:10000]:
            keyExistProxy, keyProxy = self.keyExists(baseRequestResponse)
            if not keyExistProxy:
                continue
            if key == keyProxy:
                baseRequestResponse.setHighlight(None)
        self.keys.pop(key, None)
        return

    def doHighlight(self, baseRequestResponse, key, keyExist, toolFlag):

        color = None
     
        if keyExist:
            keyValues = self.keys.get(key)
            if "Manual" in keyValues:
                color = self.colors.get("Manual")
                skip = True
            elif "Explicit" in keyValues:
                skip = True
                color = self.keys.get(key)[1]

        if toolFlag in self.automatedTools and not skip:
            # PLACEHOLDER FOR SUPPORTING HIGHLIGHTING FOR INTRUDER/SCANNER/EXTENDER
            if keyExist:
                self.keys[key].append(toolFlag)
            else:
                self.keys[key] = [toolFlag]
        if color:
            baseRequestResponse.setHighlight(color)
            self.doProxyHighlight(key, color)
    
    def doProxyHighlight(self, key, color):
        if key in self.contextMenuKeys:
            baseRequestResponse = self.contextMenuKeys.get(key)
            baseRequestResponse.setHighlight(color)
            
    def createMenuItems(self, invocation):

        items = []
        contexts = [
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_RESPONSE,
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_EDITOR_RESPONSE,
            invocation.CONTEXT_PROXY_HISTORY,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE,
        ]

        if invocation.getInvocationContext() in contexts:
            baseRequestResponse = invocation.getSelectedMessages()[0]
            parentMenu = HighlighterParentMenu().menu
            keyExist, key = self.keyExists(baseRequestResponse)
            self.contextMenuKeys[key] = baseRequestResponse

            if keyExist:
                parentMenu.add(HighlighterRemoveKeyedMenuItem(self, baseRequestResponse, key).menuitem)
            else:
                parentMenu.add(HighlighterAddKeyedMenuItem(self, baseRequestResponse, key, keyExist).menuitem)
                colorMenu = HighlighterAddKeyedMenuItemColor(self, baseRequestResponse, key, keyExist).menuitem
                parentMenu.add(colorMenu)
            items.append(parentMenu)
            return items
        else:
            pass

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if not messageIsRequest:
            return

        # If tool origin is Intruder,Scanner,or Extender then proceed to highlight

        if toolFlag not in self.tools:
            return
        
        keyExist, key = self.keyExists(messageInfo)

        self.doHighlight(messageInfo, key, keyExist, toolFlag)

    def cleanURL(self, url):

        # GUID (Optional Dash), Hashes, Any purely numeric sequence

        regexs = [
            "{?\w{8}-?\w{4}-?\w{4}-?\w{4}-?\w{12}}?",
            "^[a-fA-F0-9]{32}$",
            "^[a-fA-F0-9]{40}$",
            "^[a-fA-F0-9]{56}$",
            "^[a-fA-F0-9]{64}$",
            "^[a-fA-F0-9]{96}$",
            "^[a-fA-F0-9]{128}$",
            "^\d+$",
        ]
        temp = "(?:% s)" % "|".join(regexs)
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

    def __init__(
        self,
        extender,
        baseRequestResponse,
        key,
        keyExist,
        text="Add Highlight From Keyed Parameters",
    ):

        self.extender = extender
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(True)
        self.menuitem.addActionListener(self)
        self.baseRequestResponse = baseRequestResponse
        self.key = key
        self.keyExist = keyExist

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:
        """

        self.extender.keys[self.key] = ["Manual"]
        color = self.extender.colors.get("Manual")
        self.baseRequestResponse.setHighlight(color)

        # Higlight items 10000 items back

        history = self.extender._callbacks.getProxyHistory()
        for baseRequestResponse in history[:self.extender.proxyLookBackLimit]:
            keyExistProxy, keyProxy = self.extender.keyExists(baseRequestResponse)
            if not keyExistProxy:
                continue
            if self.key == keyProxy:
                baseRequestResponse.setHighlight(color)

        self.extender._callbacks.saveExtensionSetting("keys", str(self.extender.keys))
        
class HighlighterAddKeyedMenuItemColor(ActionListener):
    """
    HighlighterAddKeyedMenuItem creates a new submenu.
    """

    def __init__(
        self,
        extender,
        baseRequestResponse,
        key,
        keyExist,
        text="Add Highlight From Keyed Parameters (Color)",
    ):

        self.extender = extender
        self.menuitem = JMenu(text)
        self.baseRequestResponse = baseRequestResponse
        self.key = key
        self.keyExist = keyExist
        for color in self.extender.combocolors:
            self.submenu = JMenuItem(color)
            self.submenu.setEnabled(True)
            self.submenu.addActionListener(self)
            self.menuitem.add(self.submenu)
        self.menuitem.setEnabled(True)

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:
        """
        color = e.getSource().getText()
        self.extender.keys[self.key] = ["Explicit",color]
        self.baseRequestResponse.setHighlight(color)

        # Higlight items 10000 items back

        history = self.extender._callbacks.getProxyHistory()
        for baseRequestResponse in history[:self.extender.proxyLookBackLimit]:
            keyExistProxy, keyProxy = self.extender.keyExists(baseRequestResponse)
            if not keyExistProxy:
                continue
            if self.key == keyProxy:
                baseRequestResponse.setHighlight(color)

        self.extender._callbacks.saveExtensionSetting("keys", str(self.extender.keys))

class HighlighterRemoveKeyedMenuItem(ActionListener):
    """
    HighlighterRemoveKeyedMenuItem creates a new sub menu.
    """

    def __init__(
        self,
        extender,
        baseRequestResponse,
        key,
        text="Remove Highlight From Keyed Parameters",
    ):

        self.extender = extender
        self.menuitem = JMenuItem(text)
        self.menuitem.setEnabled(True)
        self.menuitem.addActionListener(self)
        self.baseRequestResponse = baseRequestResponse
        self.key = key

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:
        """

        self.extender.removeHiglight(self.key)
        self.extender._callbacks.saveExtensionSetting("keys", str(self.extender.keys))

class JComboDropDown(ActionListener):
    """
    JComboDropDown creates a new dropdown.
    """

    def __init__(self, tool, extender):

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
        self.extender._callbacks.saveExtensionSetting(self.tool, selected)
        self.extender.colors[self.tool] = selected

class FixSizeOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        if len(self) > 50:
            self.popitem(False)
