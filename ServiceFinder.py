from Zeroconfig import *
from typing import Union
from Browser import *


class ServiceFinder:
    def __init__(self) -> None:
        self.found_services = set()

    def add_service(self, zeroconfig, type, name):
        self.found_services.add(name)

    @classmethod
    def find(cls, zeroconfig=None, timeout: Union[int, float] = 5):
        if zeroconfig is None:
            local_zeroconfig = Zeroconfig()
        else:
            local_zeroconfig = zeroconfig
        listener = cls()
        browser = Browser(local_zeroconfig, '_services._dns-sd._udp.local.', listener)
        time.sleep(timeout)
        if zeroconfig is None:
            local_zeroconfig.close()
        else:
            browser.stop()

        return tuple(sorted(listener.found_services))
