# Output backends for sigmac
# Copyright 2016-2018 Thomas Patzke, Florian Roth, Roey

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
import json
import sigma
from .base import SingleTextQueryBackend
from .mixins import MultiRuleOutputMixin


class WaldoEventLogBackend(SingleTextQueryBackend):
    """Converts Sigma rule into XML used for Splunk Dashboard Panels"""
    identifier = "waldo_eventlog"
    active = True
    index_field = "index"

    reClear = None
    andToken = " and "
    orToken = " or "
    notToken = " != "
    subExpression = "(%s)"
    listExpression = "(%s)"
    listSeparator = " "
    valueExpression = "%s"
    nullExpression = "NOT _exists_:%s"
    notNullExpression = "_exists_:%s"
    mapExpression = "*[EventData[Data[@Name='%s'] = '%s']]"
    mapEventIDExpression = "Event/System[%s=%s]"
    mapListsSpecialHandling = False

    output = {
        'keywords': [],
        'not_keywords': [],
        'query': None
    }

    def generate(self, sigmaparser):
        for parsed in sigmaparser.condparsed:
            query = self.generateQuery(parsed)
            before = self.generateBefore(parsed)
            after = self.generateAfter(parsed)

            result = ""
            if before is not None:
                result = before
            if query is not None:
                result += query
            if after is not None:
                result += after

            self.output['query'] = result
            return self.output

    def generateBefore(self, parsed):
        return "<QueryList><Query><Select Path='{}'>".format(self.logsource)

    def generateAfter(self, parsed):
        return "</Select></Query></QueryList>"

    def generateANDNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            map_filtered = []
            for item in filtered:
                if '*[EventData[Data[' in item or 'Event/System[' in item:
                    map_filtered.append(item)
                else:
                    self.output['keywords'].append(item)
            return self.andToken.join(map_filtered)
        else:
            return None

    def generateORNode(self, node):
        generated = [ self.generateNode(val) for val in node ]
        filtered = [ g for g in generated if g is not None ]
        if filtered:
            return self.orToken.join(filtered)
        else:
            return None

    def generateNOTNode(self, node):
        generated = self.generateNode(node.item)
        if generated is not None:
            map_generated = []
            for item in generated:
                if '*[EventData[Data[' in item or 'Event/System[' in item:
                    map_generated.append(item)
                else:
                    self.output['not_keywords'].append(item)
            return self.notToken + map_generated
        else:
            return None

    def generateSubexpressionNode(self, node):
        generated = self.generateNode(node.items)
        if generated:
            return self.subExpression % generated
        else:
            return None

    def generateListNode(self, node):
        if not set([type(value) for value in node]).issubset({str, int}):
            raise TypeError("List values must be strings or numbers")
        return self.listExpression % (self.listSeparator.join([self.generateNode(value) for value in node]))

    def generateMapItemNode(self, node):
        key, value = node
        if self.mapListsSpecialHandling == False and type(value) in (str, int, list) or self.mapListsSpecialHandling == True and type(value) in (str, int):
            # Look for special handling first and parse appropriately
            if key == 'logsource':
                self.logsource = value
            elif key == 'EventID':
                return self.mapEventIDExpression % (key, self.generateNode(value))
            else:
                # If the value has any special characters (e.g. * or ?) we need to process it separately as well
                if type(value) is str and ('*' in value or '?' in value):
                    pass
                else:
                    return self.mapExpression % (key, self.generateNode(value))
        elif type(value) == list:
            return self.generateMapItemListNode(key, value)
        else:
            raise TypeError("Backend does not support map values of type " + str(type(value)))

    def generateMapItemListNode(self, key, value):
        return self.mapListValueExpression % (key, self.generateNode(value))

    def generateValueNode(self, node):
        return self.valueExpression % (self.cleanValue(str(node)))

    def generateNULLValueNode(self, node):
        return self.nullExpression % (node.item)

    def generateNotNULLValueNode(self, node):
        return self.notNullExpression % (node.item)
