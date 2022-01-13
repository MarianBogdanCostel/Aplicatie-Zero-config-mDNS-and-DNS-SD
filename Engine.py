import select
import threading
from DNSClasses import *


class Engine(threading.Thread):
    def __init__(self, zeroconf):
        super().__init__()
        self.zeroconf = zeroconf

        self.listeners = {}
        self.condition = threading.Condition()
        self.start()

    def add_listener(self, listener, s):
        with self.condition:
            self.listeners[s] = listener
            self.condition.notify()

    def get_listeners(self):
        with self.condition:
            result = self.listeners.keys()
        return result

    def run(self):
        while not GLOBAL_DONE:
            result = self.get_listeners()
            if len(result) == 0:

                with self.condition:
                    self.condition.wait(5)
            else:
                try:
                    rr, wr, er = select.select(result, [], [], 5)
                    for s in rr:
                        try:
                            self.listeners[s].read_data(s)
                        except Exception:
                            pass
                except Exception:
                    pass

    def notify(self):
        with self.condition:
            self.condition.notify()
