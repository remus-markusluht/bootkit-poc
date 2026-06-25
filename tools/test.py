with open('hook_handler.bin', 'rb') as f:
    data = f.read()
print(f'uint8_t hook_handler_shellcode[] = {{')
for i in range(0, len(data), 16):
    chunk = ', '.join(f'0x{b:02X}' for b in data[i:i+16])
    print(f'    {chunk},')
print('};')
marker = bytes([0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE])
print(f'// runtime_ptr_slot offset: 0x{data.index(marker):X}')