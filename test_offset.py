import ctypes
out = ctypes.create_string_buffer(100)
outl = ctypes.c_int(0)
# try byref offset
try:
    ptr = ctypes.byref(out, 10)
    print("byref offset works")
except Exception as e:
    print(e)
