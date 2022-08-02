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

# TODO
    # Setting for keying off URL and verb only
    # Setting for normalizing parameter names by removing digits (Ctl01, etc.)

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
            "Triaged": "red",
            "Interesting": "blue",
            "Finding": "cyan",
            "Ignore": "gray",
        }

        self.proxyLookBackLimit = 25000

        self.contextMenuKeys = FixSizeOrderedDict()

        # Add suite tab (This breaks if not at the end!)

        callbacks.addSuiteTab(self)

        print("Extension loaded")
        print("By Michael Maturi (amarionette) @ Mandiant")

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

        jlabel = JLabel("Auto-Highlighter Settings")
        jlabel1 = JLabel("Triaged Highlight Color")
        jlabel2 = JLabel("Interesting Highlight Color")
        jlabel3 = JLabel("Finding Highlight Color")
        jlabel4 = JLabel("Ignore Highlight Color")

        combo = JComboDropDown("Triaged", self).combobox
        combo2 = JComboDropDown("Interesting", self).combobox
        combo3 = JComboDropDown("Finding", self).combobox
        combo4 = JComboDropDown("Ignore", self).combobox

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

    def keyExists(self,key):
        result = False
        if key in self.keys:
            result = True
        return result

    def calculateKey(self, baseRequestResponse):

        requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
        
        # Handle timed-out requests which will throw an error

        if not requestInfo.getUrl():
            return None

        # Get URL and clean it

        url = requestInfo.getUrl().toString()
        url = self.cleanURL(url)

        # Get parameters that are NOT cookies and clean them

        parameters = requestInfo.getParameters()
        parameters = list(filter(lambda x: (x.getType() != x.PARAM_COOKIE), parameters))
        parameterNames = [x.getName().encode("utf-8").strip().lower() for x in parameters]
        parameterNamesString = "".join(parameterNames)

        # Create a unique identifier using CRC32

        key = zlib.crc32(url + parameterNamesString)
        return key

    def removeHiglight(self,key):
        history = self._callbacks.getProxyHistory()
        for baseRequestResponse in history[self.extender.proxyLookBackLimit:]:
            proxyHistoryItemKey = self.calculateKey(baseRequestResponse)
            if key == proxyHistoryItemKey:
                baseRequestResponse.setHighlight(None)
        self.keys.pop(key, None)
        return

    def doHighlight(self, baseRequestResponse, key):

        color = None
     
        # Check all stored keys in 'keys' dictionary (Tag,CRC32Key)
        keyValue = self.keys.get(key)[0]

        # Look up tag color in colors dictionary, and x-lookup against key's tag to determine color
        for tagKey in self.colors:
            if tagKey == keyValue:
                color = self.colors.get(tagKey)
                break
        if "Explicit" in keyValue:
            color = self.keys.get(key)[1]

        baseRequestResponse.setHighlight(color)
    
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
            key = self.calculateKey(baseRequestResponse)
            keyExist = self.keyExists(key)
            self.contextMenuKeys[key] = baseRequestResponse

            if keyExist:
                parentMenu.add(HighlighterRemoveKeyedMenuItem(self, baseRequestResponse, key).menuitem)
            else:
                parentMenu.add(HighlighterAddKeyedMenuItem(self, baseRequestResponse, key, "Triaged").menuitem)
                parentMenu.add(HighlighterAddKeyedMenuItem(self, baseRequestResponse, key, "Interesting").menuitem)
                parentMenu.add(HighlighterAddKeyedMenuItem(self, baseRequestResponse, key, "Finding").menuitem)
                parentMenu.add(HighlighterAddKeyedMenuItem(self, baseRequestResponse, key, "Ignore").menuitem)
                colorMenu = HighlighterAddKeyedMenuItemColor(self, baseRequestResponse, key).menuitem
                parentMenu.add(colorMenu)
            items.append(parentMenu)
            return items
        else:
            pass

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):

        if not messageIsRequest:
            return

        # If tool origin is not proxy, ignore

        if toolFlag != self._callbacks.TOOL_PROXY:
            return

        # Check if a key exists for this item
        key = self.calculateKey(messageInfo)
        keyExist = self.keyExists(key)
  
        if keyExist:
            self.doHighlight(messageInfo, key)

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
        tag,
        text="Add Highlight From Keyed Parameters",
    ):

        self.extender = extender
        self.menuitem = JMenuItem("{0} ({1})".format(text,tag))
        self.menuitem.setEnabled(True)
        self.menuitem.addActionListener(self)
        self.baseRequestResponse = baseRequestResponse
        self.key = key
        self.tag = tag

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:
        """

        self.extender.keys[self.key] = [self.tag]
        color = self.extender.colors.get(self.tag)
        self.baseRequestResponse.setHighlight(color)

        history = self.extender._callbacks.getProxyHistory()
        for baseRequestResponse in history[self.extender.proxyLookBackLimit:]:
            keyProxyRequest = self.extender.calculateKey(baseRequestResponse)
            if self.key == keyProxyRequest:
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
        text="Add Highlight From Keyed Parameters (Color)",
    ):

        self.extender = extender
        self.menuitem = JMenu(text)
        self.baseRequestResponse = baseRequestResponse
        self.key = key
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

        history = self.extender._callbacks.getProxyHistory()
        for baseRequestResponse in history[self.extender.proxyLookBackLimit:]:
            keyProxyRequest = self.extender.calculateKey(baseRequestResponse)
            if self.key == keyProxyRequest:
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

    def __init__(self, tag, extender):

        self.extender = extender
        self.combobox = JComboBox(self.extender.combocolors)
        self.combobox.addActionListener(self)
        self.tag = tag

        # Create combox box color based on saved value or default

        setting = self.extender._callbacks.loadExtensionSetting(self.tag)
        if setting:
            self.combobox.setSelectedItem(setting)
            self.extender.colors[self.tag] = setting
        else:
            self.combobox.setSelectedItem(self.extender.colors.get(self.tag))

    def actionPerformed(self, e):
        """
        Override the ActionListener method. Usually setup in combination with a menuitem click.
        :param e: unused
        :return:

        """

        selected = self.combobox.getSelectedItem()
        self.extender._callbacks.saveExtensionSetting(self.tag, selected)
        self.extender.colors[self.tag] = selected

class FixSizeOrderedDict(OrderedDict):
    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        if len(self) > 50:
            self.popitem(False)
