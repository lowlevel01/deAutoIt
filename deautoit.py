from autoit_ripper import extract, AutoItVersion
import os
import sys
import re
from Crypto.Cipher import ARC4
import lznt1
import argparse
import pefile

def extract_repeating_pattern(s):
    n = len(s)
    z = [0]*n
    for i in range(1, n):
        while i + z[i] < n and s[z[i]] == s[i+z[i]]:
              z[i] += 1

    last_index = z.index(max(z))
    return s[:last_index]

def isPe(path):
    try:
        pe = pefile.PE(path)
        return True
    except pefile.PEFormatError:
        return False
        
def xor_artefact(name, enc_exe):
    dos_header = b"\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x01\x00\x00"
    includes_key = ""
    for (dos, enc) in zip(dos_header, enc_exe):
        includes_key += chr(dos ^ enc)

    key = extract_repeating_pattern(includes_key)
    enc_exe = bytearray(enc_exe)
    for i in range(len(enc_exe)):
        enc_exe[i] = enc_exe[i] ^ ord(key[i % len(key)])
    with open(name+"-dec.exe", "wb") as stage2:
        stage2.write(enc_exe)
    if isPe(name+"-dec.exe"):
        print(f"Found a valid PE File: Saved As {name}-dec.exe")
        return True
    else:
        os.remove(name+"-dec.exe")
        return False



def rc4_decrypt(ciphertext, key):
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def decompress_lznt1(data):
    return lznt1.decompress(data)

def find_encryption_key(text, real_name):
    pattern = rf'Binary\s*\(\s*\${re.escape(real_name)}\s*\)\s*,\s*Binary\s*\(\s*"([^"]+)"\s*\)'
    match = re.search(pattern, text)
    if match:
        return match.group(1)
    return None

def find_encryption_key_from_script(file, real_name):
    text = open(file, "r").read()
    pattern = rf'Binary\s*\(\s*\${re.escape(real_name)}\s*\)\s*,\s*Binary\s*\(\s*"([^"]+)"\s*\)'
    match = re.search(pattern, text)
    if match:
        return match.group(1)
    return None

def script_analyze(content):
        try:
            text_file = content.decode()
            content = content.decode()
        except:
            text_file = content
        pattern = re.compile(r'".{1000,}"')
        if isinstance(content, str):
            content = content.replace("\t","").split("\r\n")
        else:
            content = content.decode().replace("\t","").split("\r\n")

        previous_name = ""
        current_name = ""
        next_name = ""
        shellcode = ""
        variable_name = ""
        matched_lines = []
        for i in range(len(content)):
            line = content[i]
            line = line.strip()
            if pattern.search(line):
                matched_lines.append(line)

        for i in range(1, len(matched_lines) - 1):
            previous_name = matched_lines[i-1].split(" ")[0]
            current_name = matched_lines[i].split(" ")[0]
            next_name = matched_lines[i+1].split(" ")[0]

            if current_name == next_name and current_name == previous_name:
                variable_name = current_name
                break

        for i in range(len(matched_lines)):
            name = matched_lines[i].split(" ")[0]
            if name == variable_name:
                shellcode_part = matched_lines[i].split(" ")[-1].replace("\"", "")
                shellcode += shellcode_part

        if shellcode.startswith("0x"):
            shellcode = shellcode[2:]

        b_shellcode = bytearray.fromhex(shellcode)

        b_key = find_encryption_key(text_file, variable_name.lstrip("$"))
        if b_key:
            b_key = b_key.encode()
            dec_shellcode = rc4_decrypt(b_shellcode, b_key)

            file = open("stage2-decrypted.exe", "wb").write(dec_shellcode)
            if isPe("stage2-decrypted.exe"):
                print("Found a valid PE: Saved as stage2-decrypted.exe")
            else:
                os.remove("stage2-decrypted.exe")
            
            
            decompressed_shellcode = decompress_lznt1(dec_shellcode)

            file = open("stage2-decompressed.exe", "wb").write(decompressed_shellcode)
            if isPe("stage2-decompressed.exe"):
                print("Found a valid PE: Saved as stage2-decompressed.exe")
            else:
                os.remove("stage2-decompressed.exe")
        

        
def main():
    parser = argparse.ArgumentParser(description='A tool to automate extraction of stage 2 of some cases of malware using AutoIt.')
    parser.add_argument("-s", "--script",help="Work directly on the script (deobfuscate strings before using it)")
    parser.add_argument("-a", "--autoit",help="extract the script and embedded files then work on them")

    args = parser.parse_args()

    if len(sys.argv) < 3:
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.autoit:
        file_content = open(args.autoit, "rb").read()
        content_list = extract(data=file_content)

        #AutoIt script and other files
        if len(content_list) > 1:
            script_analyze(content_list[0][1])
            for i in range(1, len(content_list)):
                name = content_list[i][0]
                content = content_list[i][1]
                try:
                    xor_artefact(name, content)
                except:
                    pass

        # A single AutoIt script
        if len(content_list) == 1:
            script_analyze(content_list[0][1])

    if args.script:
        content = open(args.script, "rb").read()
        script_analyze(content)

if __name__ == "__main__":
    main()
