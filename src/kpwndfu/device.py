import checkm8.usbexec as usbexec
from checkm8.checkm8 import exploit
from checkm8.device import DFUDevice


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
