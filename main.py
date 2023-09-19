import os
import sys
import platform
from tkinter import filedialog as fd

# SubZeroX, written by socialfright on GitHub
banner = """"
   _____       __ _____                  _  __
  / ___/__  __/ //__  /  ___  _________ | |/ /
  \__ \/ / / / __ \/ /  / _ \/ ___/ __ \|   / 
 ___/ / /_/ / /_/ / /__/  __/ /  / /_/ /   |  
/____/\__,_/_.___/____/\___/_/   \____/_/|_|                                                                                   
"""
# -- OFFSETS WINDOWS
INITIAL_LICENSE_CHECK = {
    "offset": 0x00415013,
    "value": b"\x55\x41\x57\x41\x56\x41\x55\x41",
    "patch": b"\x48\xC7\xC0\x00\x00\x00\x00\xC3",
    "cmp": 0x8
}
PERSISTENT_LICENSE_CHECK = {
    "offset": 0x00409037,
    "value": b"\xE8\xC0\xCC\x12\x00",
    "patch": b"\x90\x90\x90\x90\x90",
    "cmp": 0x5
}
PERSISTENT_LICENSE_CHECK_2 = {
    "offset": 0x0040904F,
    "value": b"\xE8\xA8\xCC\x12\x00",
    "patch": b"\x90\x90\x90\x90\x90",
    "cmp": 0x5
}
LICENSE_NOTIFY_THREAD_OFF = {
    "offset": 0x00416CA4,
    "value": b"\x55",
    "patch": b"\xC3",
    "cmp": 0x1
}
DISABLE_CRASH_REPORTER_OFF = {
    "offset": 0x00416CA4,
    "value": b"\x41",
    "patch": b"\xC3",
    "cmp": 0x1
}
# -- OFFSETS WINDOWS
INITIAL_LICENSE_CHECK_WINDOWS = {
    "offset": 0x000A8D78,
    "value": b"\x55\x41\x57\x41\x56\x41\x55\x41",
    "patch": b"\x48\xC7\xC0\x00\x00\x00\x00\xC3",
    "cmp": 0x8
}
PERSISTENT_LICENSE_CHECK_WINDOWS = {
    "offset": 0x00071D0,
    "value": b"\xE8\x17\xFE\x20\x00",
    "patch": b"\x90\x90\x90\x90\x90",
    "cmp": 0x5
}
PERSISTENT_LICENSE_CHECK_2_WINDOWS = {
    "offset": 0x00071E9,
    "value": b"\xE8\xFE\xFD\x20\x00",
    "patch": b"\x90\x90\x90\x90\x90",
    "cmp": 0x5
}
LICENSE_NOTIFY_THREAD_OFF_WINDOWS = {
    "offset": 0x000AAB3E,
    "value": b"\x55",
    "patch": b"\xC3",
    "cmp": 0x1
}
DISABLE_CRASH_REPORTER_OFF_WINDOWS = {
    "offset": 0x000A8945,
    "value": b"\x55",
    "patch": b"\xC3",
    "cmp": 0x1
}


def check_binary(path):
    with open(path, 'rb') as file:
        content = file.read(512)  # Reading the first 512 bytes of the file

    if content.startswith(b'\x4D\x5A'):  # MZ header for Windows Executables (PE files)
        print(f"[>] Windows PE: Detected -> {os.path.getsize(path)}")
        patch_windows(path)
    if content.startswith(b'\x7F\x45\x4C\x46'):  # ELF header for Linux Executables
        print(f"[>] Linux ELF: Detected -> {os.path.getsize(path)}")
        patcher_linux(path)
    if content.startswith(b'\xCE\xFA\xED\xFE') or content.startswith(
            b'\xCF\xFA\xED\xFE'):  # Mach-O header for macOS Executables
        return 'Mac'

    return 'Unknown'


def patcher_linux(binary):
    con_l = input("Continue? Y/N")
    if con_l.upper() == 'Y':
        F = open(binary, "rb+")
        F.seek(INITIAL_LICENSE_CHECK["offset"])
        data = F.read(INITIAL_LICENSE_CHECK["cmp"])
        if data == INITIAL_LICENSE_CHECK["value"]:
            print(f"[+] Found unpatched value for 'isValidLicense'at 0x{INITIAL_LICENSE_CHECK['offset']:x}")
            F.seek(INITIAL_LICENSE_CHECK["offset"])
            F.write(INITIAL_LICENSE_CHECK["patch"])
            print(f"[+] Writing patch --- {INITIAL_LICENSE_CHECK['value']} --> {INITIAL_LICENSE_CHECK['patch']}")
        F.seek(PERSISTENT_LICENSE_CHECK["offset"])
        data = F.read(PERSISTENT_LICENSE_CHECK["cmp"])
        if data == PERSISTENT_LICENSE_CHECK["value"]:
            print(f"[+] Found unpatched value for 'invalidationFunction'at 0x{PERSISTENT_LICENSE_CHECK['offset']:x}")
            F.seek(PERSISTENT_LICENSE_CHECK["offset"])
            F.write(PERSISTENT_LICENSE_CHECK["patch"])
            print(f"[+] Writing patch --- {PERSISTENT_LICENSE_CHECK['value']} --> {PERSISTENT_LICENSE_CHECK['patch']}")
        F.seek(PERSISTENT_LICENSE_CHECK_2["offset"])
        data = F.read(PERSISTENT_LICENSE_CHECK_2["cmp"])
        if data == PERSISTENT_LICENSE_CHECK_2["value"]:
            print(f"[+] Found unpatched value for 'validationFunction' at 0x{PERSISTENT_LICENSE_CHECK_2['offset']:x}")
            F.seek(PERSISTENT_LICENSE_CHECK_2["offset"])
            F.write(PERSISTENT_LICENSE_CHECK_2["patch"])
            print(
                f"[+] Writing patch --- {PERSISTENT_LICENSE_CHECK_2['value']} --> {PERSISTENT_LICENSE_CHECK_2['patch']}")
        F.seek(LICENSE_NOTIFY_THREAD_OFF["offset"])
        data = F.read(LICENSE_NOTIFY_THREAD_OFF["cmp"])
        if data == LICENSE_NOTIFY_THREAD_OFF["value"]:
            print(f"[+] Found unpatched value for 'licenseNotifyThread' at 0x{LICENSE_NOTIFY_THREAD_OFF['offset']:x}")
            F.seek(LICENSE_NOTIFY_THREAD_OFF["offset"])
            F.write(LICENSE_NOTIFY_THREAD_OFF["patch"])
            print(
                f"[+] Writing patch --- {LICENSE_NOTIFY_THREAD_OFF['value']} --> {LICENSE_NOTIFY_THREAD_OFF['patch']}")
        F.seek(DISABLE_CRASH_REPORTER_OFF["offset"])
        data = F.read(DISABLE_CRASH_REPORTER_OFF["cmp"])
        if data == DISABLE_CRASH_REPORTER_OFF["value"]:
            print(f"[+] Found unpatched value for 'crashReporter' at 0x{DISABLE_CRASH_REPORTER_OFF['offset']:x}")
            F.seek(DISABLE_CRASH_REPORTER_OFF["offset"])
            F.write(DISABLE_CRASH_REPORTER_OFF["patch"])
            print(
                f"[+] Writing patch --- {DISABLE_CRASH_REPORTER_OFF['value']} --> {DISABLE_CRASH_REPORTER_OFF['patch']}")
        print(f"[=] Saving file to {binary}")
        F.close()
        print(f"[+] DONE =]")
    elif con_l.upper() == 'N':
        print("Exiting...")
        exit()
    else:
        print("No Input ")
        exit()


def patch_windows(binary):
    con_l = input("Continue? Y/N")
    if con_l.upper() == 'Y':
        F = open(binary, "rb+")
        F.seek(INITIAL_LICENSE_CHECK_WINDOWS["offset"])
        data = F.read(INITIAL_LICENSE_CHECK_WINDOWS["cmp"])
        if data == INITIAL_LICENSE_CHECK_WINDOWS["value"]:
            print(f"[+] Found unpatched value for 'isValidLicense' at 0x{INITIAL_LICENSE_CHECK_WINDOWS['offset']:x}")
            F.seek(INITIAL_LICENSE_CHECK_WINDOWS["offset"])
            F.write(INITIAL_LICENSE_CHECK_WINDOWS["patch"])
            print(
                f"[+] Writing patch --- {INITIAL_LICENSE_CHECK_WINDOWS['value']} --> {INITIAL_LICENSE_CHECK_WINDOWS['patch']}")
        F.seek(PERSISTENT_LICENSE_CHECK_WINDOWS["offset"])
        data = F.read(PERSISTENT_LICENSE_CHECK_WINDOWS["cmp"])
        if data == PERSISTENT_LICENSE_CHECK_WINDOWS["value"]:
            print(
                f"[+] Found unpatched value for 'invalidationFunction' at 0x{PERSISTENT_LICENSE_CHECK_WINDOWS['offset']:x}")
            F.seek(PERSISTENT_LICENSE_CHECK_WINDOWS["offset"])
            F.write(PERSISTENT_LICENSE_CHECK_WINDOWS["patch"])
            print(
                f"[+] Writing patch --- {PERSISTENT_LICENSE_CHECK_WINDOWS['value']} --> {PERSISTENT_LICENSE_CHECK_WINDOWS['patch']}")
        F.seek(PERSISTENT_LICENSE_CHECK_2_WINDOWS["offset"])
        data = F.read(PERSISTENT_LICENSE_CHECK_2_WINDOWS["cmp"])
        if data == PERSISTENT_LICENSE_CHECK_2_WINDOWS["value"]:
            print(
                f"[+] Found unpatched value for 'validationFunction' at 0x{PERSISTENT_LICENSE_CHECK_2_WINDOWS['offset']:x}")
            F.seek(PERSISTENT_LICENSE_CHECK_2_WINDOWS["offset"])
            F.write(PERSISTENT_LICENSE_CHECK_2_WINDOWS["patch"])
            print(
                f"[+] Writing patch --- {PERSISTENT_LICENSE_CHECK_2_WINDOWS['value']} --> {PERSISTENT_LICENSE_CHECK_2_WINDOWS['patch']}")
        F.seek(LICENSE_NOTIFY_THREAD_OFF_WINDOWS["offset"])
        data = F.read(LICENSE_NOTIFY_THREAD_OFF_WINDOWS["cmp"])
        if data == LICENSE_NOTIFY_THREAD_OFF_WINDOWS["value"]:
            print(
                f"[+] Found unpatched value for 'licenseNotifyThread' at 0x{LICENSE_NOTIFY_THREAD_OFF_WINDOWS['offset']:x}")
            F.seek(LICENSE_NOTIFY_THREAD_OFF_WINDOWS["offset"])
            F.write(LICENSE_NOTIFY_THREAD_OFF_WINDOWS["patch"])
            print(
                f"[+] Writing patch --- {LICENSE_NOTIFY_THREAD_OFF_WINDOWS['value']} --> {LICENSE_NOTIFY_THREAD_OFF_WINDOWS['patch']}")
        F.seek(DISABLE_CRASH_REPORTER_OFF_WINDOWS["offset"])
        data = F.read(DISABLE_CRASH_REPORTER_OFF_WINDOWS["cmp"])
        if data == DISABLE_CRASH_REPORTER_OFF_WINDOWS["value"]:
            print(
                f"[+] Found unpatched value for 'crashReporter' at 0x{DISABLE_CRASH_REPORTER_OFF_WINDOWS['offset']:x}")
            F.seek(DISABLE_CRASH_REPORTER_OFF_WINDOWS["offset"])
            F.write(DISABLE_CRASH_REPORTER_OFF_WINDOWS["patch"])
            print(
                f"[+] Writing patch --- {DISABLE_CRASH_REPORTER_OFF_WINDOWS['value']} --> {DISABLE_CRASH_REPORTER_OFF_WINDOWS['patch']}")
        print(f"[=] Saving file to {binary}")
        F.close()
        print(f"[+] DONE =]")
    elif con_l.upper() == 'N':
        print("Exiting...")
        exit()
    else:
        print("No Input ")
        exit()


if __name__ == "__main__":
    print(banner)
    print("[-] sublime patch for 4154 linux and windows x64, python port")
    print("[+++] DISCLAIMER, Linux x64 patches have been untested in this script [+++]")
    if os.name == 'nt':
        print("[+] auto select using gui for platform windows")
        file_path = fd.askopenfilename()
        check_binary(file_path)
    else:
        if len(sys.argv) < 2:
            print(f"[=] Arguments not set, use: {__file__} [path_to_sublime_text]")
            exit(1)
        check_binary(sys.argv[1])
