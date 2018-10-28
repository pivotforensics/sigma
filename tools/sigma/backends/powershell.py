# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, Roey, Karneades

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import re
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin

class PowerShellBackend(SingleTextQueryBackend):
    """Converts Sigma rule into PowerShell event log cmdlets."""
    identifier = "powershell"
    active = True
    options = (
        ("csv", False, "Return the results in CSV format instead of Powershell objects", None),
    )

    #reEscape = re.compile('("|\\\\(?![*?])|\+)')
    reClear = None
    andToken = " -and "
    orToken = " -or "
    notToken = " -not "
    subExpression = "(%s)"
    listExpression = "($_.message -match %s)"
    listSeparator = "$_.message -match "
    valueExpression = "\"%s\""
    nullExpression = "$_.message -notcontains \"%s\""
    notNullExpression = "$_.message -contains \"%s\""
    mapExpression = "$_.%s -eq %s"
    mapListsSpecialHandling = True

    logname = None
    eventids = []

    def generate(self, sigmaparser):
        """Method is called for each sigma rule and receives the parsed rule (SigmaParser)"""
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed, sigmaparser)

            result = self.generateBefore(parsed, query)
            if not query:
                if parsed.parsedAgg:
                    powershellSuffixAgg = self.generateAggregation(parsed.parsedAgg)
                    result += powershellSuffixAgg
                else:
                    result += " | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message"
            else:
                result += query
            result += self.generateAfter(parsed)

            # Remove an always true clause (happens for lists of evdent ids since we replace them)
            result = result.replace(' | where { (1) }', '')

            return result

    def generateBefore(self, parsed, query):
        # If we have a query (aka we have more than just a log source and event IDs), process differently
        # NOTE: The $logs check prepended to some of the commands are due to situations where on Win8.1+ there
        # are often more than 256+ event log files and PS throws "The data is invalid" errors.  This is not a
        # perfect solution, but it works for now by only processing files with records in them (typically not more
        # than 100-150 log files)
        if query:
            if self.logname and self.eventids:
                return "Get-WinEvent -FilterHashtable @{{LogName=\"{}\"; ID={}}} | where {{ ".format(self.logname, ','.join(self.eventids))
            elif self.logname:
                return "Get-WinEvent -LogName %s | where { " % self.logname
            elif self.eventids:
                return "$logs = Get-WinEvent -ListLog * | Where-Object {{$_.RecordCount}} | Select-Object -ExpandProperty LogName; Get-WinEvent -FilterHashtable @{{LogName=$logs; ID={}}} | where {{".format(','.join(self.eventids))
            return "$logs = Get-WinEvent -ListLog * | Where-Object {{$_.RecordCount}} | Select-Object -ExpandProperty LogName; Get-WinEvent -FilterHashtable @{{LogName=$logs}} | where { "
        else:
            if self.logname and self.eventids:
                return "Get-WinEvent -FilterHashtable @{{LogName=\"{}\"; ID={}}}".format(self.logname, ','.join(self.eventids))
            elif self.logname:
                return "Get-WinEvent -LogName %s" % self.logname
            elif self.eventids:
                return "$logs = Get-WinEvent -ListLog * | Where-Object {{$_.RecordCount}} | Select-Object -ExpandProperty LogName; Get-WinEvent -FilterHashtable @{{LogName=$logs; ID={}}}".format(','.join(self.eventids))
            return "$logs = Get-WinEvent -ListLog * | Where-Object {{$_.RecordCount}} | Select-Object -ExpandProperty LogName; Get-WinEvent -FilterHashtable @{{LogName=$logs}}"

    def generateAfter(self, parsed):
        if self.csv:
            return " | ConvertTo-CSV -NoTypeInformation"
        return ""

    def generateNode(self, node):
        if type(node) == sigma.parser.condition.ConditionAND:
            return self.generateANDNode(node)
        elif type(node) == sigma.parser.condition.ConditionOR:
            return self.generateORNode(node)
        elif type(node) == sigma.parser.condition.ConditionNOT:
            return self.generateNOTNode(node)
        elif type(node) == sigma.parser.condition.ConditionNULLValue:
            return self.generateNULLValueNode(node)
        elif type(node) == sigma.parser.condition.ConditionNotNULLValue:
            return self.generateNotNULLValueNode(node)
        elif type(node) == sigma.parser.condition.NodeSubexpression:
            return self.generateSubexpressionNode(node)
        elif type(node) == tuple:
            return self.generateMapItemNode(node)
        elif type(node) in (str, int):
            return self.generateValueNode(node, False)
        elif type(node) == list:
            return self.generateListNode(node)
        else:
            raise TypeError("Node type %s was not expected in Sigma parse tree" % (str(type(node))))

    def generateQuery(self, parsed, sigmaparser):
        result = self.generateNode(parsed.parsedSearch)
        self.parsedlogsource = sigmaparser.get_logsource().service

        if parsed.parsedAgg:
            if result:
                powershellSuffixAgg = self.generateAggregation(parsed.parsedAgg)
                result = result + " } " + powershellSuffixAgg
        else:
            if result:
                result += " } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message"
        return result

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            if key in ("LogName","source"):
                self.logname = value
            elif key in ("ID", "EventID"):
                if key == "EventID":
                    key = "ID"
                if str(value) not in self.eventids:
                    self.eventids.append(str(value))
            else:
                # General handling here...
                if type(value) == str and "*" in value:
                    value = normalize_value(value, keypresent=True)
                    return "$_.message -match %s" % (self.generateValueNode(add_wildcard(key) + ".*" + value, True))
                elif type(value) in (str, int):
                    value = normalize_value(value, keypresent=True)
                    return '$_.message -match %s' % (self.generateValueNode(add_wildcard(key) + ".*" + value, True))
                else:
                    return self.mapExpression % (add_wildcard(key), self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        itemslist = list()
        for item in value:
            if key in ("ID", "EventID"):
                if key == "EventID":
                    key = "ID"
                if str(item) not in self.eventids:
                    self.eventids.append(str(item))
            else:
                # General list handling here...
                if type(item) == 'str' and "*" in item:
                    item = normalize_value(item, keypresent=True)
                    itemslist.append('$_.message -match %s' % (self.generateValueNode(add_wildcard(key) + ".*" + item, True)))
                else:
                    item = normalize_value(item)
                    itemslist.append('$_.message -match %s' % (self.generateValueNode(item, True)))
        if itemslist:
            return '('+" -or ".join(itemslist)+')'
        return '1' # true

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.andToken.join(filtered)
        else:
            return None

    def generateValueNode(self, node, keypresent):
        if keypresent == False:
            node = normalize_value(node)
            return "$_.message -match \"{0}\"".format(node)
        else:
            return self.valueExpression % (self.cleanValue(str(node)))

    def getPowerShellCondOp(self, cond_op):
        if(cond_op == "<"):
            return "-lt"
        elif(cond_op == ">"):
            return "-gt"
        elif(cond_op == "="):
            return "-eq"

    def generateAggregation(self, agg):
        if agg == None:
            return ""
        if agg.aggfunc != sigma.parser.condition.SigmaAggregationParser.AGGFUNC_COUNT:
            raise NotImplementedError("Only COUNT aggregation function is implemented for this backend")
        if agg.aggfunc == sigma.parser.condition.SigmaAggregationParser.AGGFUNC_NEAR:
            # python .\tools\sigmac -t splunk -c .\tools\config\splunk-windows-all.yml -r .\rules\windows\builtin\
            # Example rule: .\sigma\rules\windows\builtin\win_susp_samr_pwset.yml
            raise NotImplementedError("The 'near' aggregation operator is not yet implemented for this backend")
        if agg.groupfield == None:
            # Example rule: .\sigma\rules\windows\builtin\win_multiple_suspicious_cli.yml
            powershell_cond_op = self.getPowerShellCondOp(agg.cond_op)
            return " | group-object %s | where { $_.count %s %s } | select name,count | sort -desc" % (agg.aggfield or "", powershell_cond_op, agg.condition)
        else:
            # Example rule: .\sigma\rules\windows\other\win_rare_schtask_creation.yml
            powershell_cond_op = self.getPowerShellCondOp(agg.cond_op)
            if (agg.aggfield == None):
                return " | group-object %s | where { $_.count %s %s } | select name,count | sort -desc" % (agg.groupfield or "", powershell_cond_op, agg.condition)
            else:
                return " | select %s, %s | group %s | foreach { [PSCustomObject]@{'%s'=$_.name;'Count'=($_.group.%s | sort -u).count} }  | sort count -desc | where { $_.count %s %s }" % (agg.groupfield, agg.aggfield, agg.groupfield, agg.groupfield, agg.aggfield, powershell_cond_op, agg.condition)


def normalize_value(value, keypresent=False):
    """Normalize the value so it will process through Powershell appropriately"""
    value = str(value)

    if keypresent:
        if value[0] == '*':
            value = value[1:]
    value = value.replace("*", ".*")
    value = value.replace('\\', '\\\\')
    value = value.replace('(', '\\(')
    value = value.replace(')', '\\)')
    value = value.replace('"', '`"')

    return value


def add_wildcard(key):
    """Allow whitespace before all capital letters in the key (typically needed)"""
    return re.sub(r"(\w)([A-Z])", r"\1\\s*\2", key)
