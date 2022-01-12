from zeroconfig import *
from typing import Union
from Browser import *


class ZeroconfigServiceTypes:
    def __init__(self) -> None:
        self.found_services = set()

    def add_service(self, zeroconfig, type, name):
        self.found_services.add(name)

    @classmethod
    def find(
            cls,
            zc=None,
            timeout: Union[int, float] = 5,
            interfaces=InterfaceChoice.Default,
            ip_version=None):
        if zc is None:
            local_zc = Zeroconfig(interfaces=interfaces)
        else:
            local_zc = zc
        listener = cls()
        browser = Browser(local_zc, '_services._dns-sd._udp.local.', listener=listener)
        time.sleep(timeout)
        if zc is None:
            local_zc.close()
        else:
            browser.cancel()

        return tuple(sorted(listener.found_services))
