import threading
from queryTypes import *


class Cleaner(threading.Thread):
    def __init__(self, zeroconfig):
        super().__init__()
        self.daemon = True
        self.zeroconfig = zeroconfig
        self.start()

    def run(self):
        while True:
            self.zeroconfig.wait(10 * 1000)
            if GLOBAL_DONE:
                return
            now = current_time_millis()
            for record in self.zeroconfig.cache.get_items():
                if record.is_expired(now):
                    self.zeroconfig.update_record(now, record)
                    self.zeroconfig.cache.remove_item(record)
