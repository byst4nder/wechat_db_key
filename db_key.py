import pefile
import re
import capstone
import struct

pe = pefile.PE("D:\\360\\3.9.5.81\\WeChatWin.dll")

target_bytes = b"\x4F\x6E\x20\x53\x65\x74\x20\x49\x6E\x66\x6F\x20\x69\x6E\x66\x6F\x20\x6D\x64\x35"
def find_byte_sequence(data, pattern):
    return [m.start() for m in re.finditer(re.escape(pattern), data)]

rdata_sections = [section for section in pe.sections if b'.rdata' in section.Name]
data_offset = 0
for section in rdata_sections:
    section_data = section.get_data()
    start_address = section.VirtualAddress
    matches = find_byte_sequence(section_data, target_bytes)
    if matches:
        for offset in matches:
            data_offset = offset + section.VirtualAddress
            #print(f"{data_offset:04x}")

target_bytes = b"\x48\x8D\x05"
code_sections = [section for section in pe.sections if b'.text' in section.Name]
for section in code_sections:
    section_data = section.get_data()
    start_address = section.VirtualAddress
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    matches = find_byte_sequence(section_data, target_bytes)
    if matches:
        for offset in matches:
            inst = list(cs.disasm(section_data[offset:offset+7], offset+start_address))[0]
            unpacked_value = struct.unpack("<I", inst.bytes[3:])[0]
            if inst.address+ inst.size + unpacked_value  == data_offset:
                instructions = list(cs.disasm(section_data[inst.address-start_address:inst.address-start_address+256], inst.address))
                call = 0
                for inst in instructions:
                    if inst.mnemonic == "call":
                        call =  call+1
                        if call == 2:
                            addr = int(inst.op_str, 16)
                            instructions = list(cs.disasm(section_data[addr-start_address:addr-start_address+256], addr))
                            for inst in instructions:
                                # print(f"{inst.address:04x}: {inst.mnemonic} {inst.op_str}")
                                opcode = inst.bytes
                                if len(opcode) == 1 and opcode[0] == 0xC3:
                                    break
                                if len(opcode) > 3:
                                    if opcode[0] == 0x48 and opcode[1] == 0x8D and opcode[2] == 0x05:
                                        unpacked_value = struct.unpack("<I", opcode[3:])[0]
                                        as_addr = inst.address+inst.size+unpacked_value
                                        dbkey_offset = 1760
                                        print("final AccoutService addr:", as_addr,hex(as_addr))
                                        print("final DBkey addr:", as_addr+dbkey_offset,hex(as_addr+dbkey_offset))
                


                    
                break



                





