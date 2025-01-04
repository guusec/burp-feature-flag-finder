from burp import IBurpExtender, IScannerCheck, IScanIssue
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Feature Flag Finder")
        callbacks.registerScannerCheck(self)
        callbacks.issueAlert("Registered Flag Finder...")
        print( "Feature Flag Finder extension loaded." )
        return

    def getResponseHeadersAndBody(self, content):
        response = content.getResponse()
        response_data = self._helpers.analyzeResponse(response)
        headers = list(response_data.getHeaders())
        body = response[response_data.getBodyOffset():].tostring()
        return headers, body

    def valid_v1_flags(self, flags):
        # To look for flag we check if a valid pattern exists for a flag 
        pattern = '(is|is_|enable|disable|toggle|show|hide)[a-z]+\w*":\w*(true|false|1|0)'
        match = re.search(pattern, flags, flags=re.IGNORECASE)
        return bool(match)

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        headers, body = self.getResponseHeadersAndBody(baseRequestResponse)

        # Test the body for flags
        if self.valid_v1_flags(body):
            self._callbacks.issueAlert("Found potential valid feature flag(s) in body.")

            # report the issue
            issues.append( flagScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                [baseRequestResponse]
            ))

        if not issues:
            issues = None

        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

class flagScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return "Possible feature flag(s) detected"

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return "Medium"

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return "The response contains potential feature flags."

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
