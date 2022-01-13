from functools import reduce
from DNSClasses import *


class DNSCache:
    def __init__(self):
        self.items = {}

    def add_item(self, item):
        self.items.setdefault(item.key, []).append(item)

    def remove_item(self, item):
        try:
            list = self.items[item.key]
            list.remove(item)
            if not list:
                del self.items[item.key]
        except (KeyError, ValueError):
            pass

    def get_item(self, item):
        try:
            list = self.items[item.key]
            return list[list.index(item)]
        except (KeyError, ValueError):
            return None

    def get_item_by_details(self, name, type, clazz):
        item = DNSEntry(name, type, clazz)
        return self.get_item(item)

    def get_items(self):
        if not self.items:
            return []
        else:
            return reduce(lambda x, y: x + y, self.items.values())

    def get_item_with_name(self, name):
        try:
            return self.items[name]
        except KeyError:
            return []
