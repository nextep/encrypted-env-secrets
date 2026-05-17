import ctypes
import os

def wipe_environ_key(key_to_wipe):
    libc = ctypes.CDLL(None)
    try:
        environ_ptr = ctypes.POINTER(ctypes.c_char_p).in_dll(libc, "environ")
    except ValueError:
        return # 'environ' not exported
        
    i = 0
    while environ_ptr[i] is not None:
        env_str = environ_ptr[i]
        # Decode up to the first =
        try:
            # We can't just decode the whole thing because we want to overwrite it in place
            # Let's read the bytes until \0
            j = 0
            while True:
                # To read memory, we need to cast to POINTER(c_char)
                char_ptr = ctypes.cast(environ_ptr, ctypes.POINTER(ctypes.POINTER(ctypes.c_char)))[i]
                
                # Let's just use ctypes.string_at
                s = ctypes.string_at(environ_ptr[i])
                if s.startswith(key_to_wipe.encode() + b'='):
                    # Found it! Let's memset the whole string
                    libc.memset(environ_ptr[i], 0, len(s))
                    print(f"Wiped {key_to_wipe}")
                    return
                break
        except Exception as e:
            print("Error", e)
        i += 1

os.environ["SUPER_SECRET"] = "my_secret_value"
wipe_environ_key("SUPER_SECRET")

# Check if it's wiped from /proc/self/environ
with open(f"/proc/{os.getpid()}/environ", "rb") as f:
    env_data = f.read()
    if b"SUPER_SECRET=my_secret_value" in env_data:
        print("FAILED: Secret still in /proc/self/environ")
    else:
        print("SUCCESS: Secret wiped from /proc/self/environ")
