import sys
import os

def main():
    if len(sys.argv) < 2:
        print("Usage: python embed_bootkit.py <path_to_bootkit.efi>")
        sys.exit(1)

    efi_path = sys.argv[1]
    try:
        with open(efi_path, 'rb') as f:
            data = f.read()
    except FileNotFoundError:
        print(f"Error: Could not find {efi_path}")
        sys.exit(1)

    array_lines = []
    array_lines.append("// ==================== EMBEDDED BOOTKIT ====================")
    array_lines.append("// Auto-generated from bootkit.efi - DO NOT EDIT MANUALLY")
    array_lines.append("unsigned char bootkit_image[] = {")
    for i in range(0, len(data), 16):
        chunk = ', '.join(f'0x{b:02X}' for b in data[i:i+16])
        array_lines.append(f"    {chunk},")
    array_lines.append("};")
    array_lines.append(f"UINTN bootkit_size = sizeof(bootkit_image);")
    array_lines.append("// =======================================================")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.abspath(os.path.join(script_dir, "..", "edk2", "generated", "bootkit_embedded.hpp"))

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(array_lines))

    print(f"Successfully embedded {len(data)} bytes into {output_path}")

if __name__ == "__main__":
    main()
