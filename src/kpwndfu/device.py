import checkm8.dfu as dfu
import checkm8.usbexec as usbexec


def demote():
    device = dfu.acquire_device()
    serial_number = device.serial_number
    dfu.release_device(device)

    if 'PWND:[checkm8]' in serial_number:
        pwned = usbexec.PwnedUSBDevice()
        old_value = pwned.read_memory_uint32(pwned.platform.demotion_reg)
        print(f'Demotion Register: 0x{hex(old_value)}')
        if old_value & 1:
            print('Attempting demotion')
            pwned.write_memory_uint32(pwned.platform.demotion_reg, old_value & 0xFFFFFFFE)
            new_value = pwned.read_memory_uint32(pwned.platform.demotion_reg)
            print(f'Demotion Register: 0x{hex(new_value)}')
            if old_value != new_value:
                print(f'Success')
            else:
                print(f'Failed to demote device')
        else:
            print(f'Device is already demoted!')
    else:
        print('dfu is not pwn')
