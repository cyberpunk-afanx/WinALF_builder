import pefile
import sys

def banner():
    print('''
 _    _ _        ___  ______ _     
| |  | (_)      / _ \ |  ___| |    
| |  | |_ _ __ / /_\ \| |_  | |    
| |/\| | | '_ \|  _  ||  _| | |    
\  /\  / | | | | | | || |   | |____
 \/  \/|_|_| |_\_| |_/\_|   \_____/
    
    ''')

def parse_pe_file(file_path):
    # Load the PE file
    pe = pefile.PE(file_path)

    # Basic information
    print("PE File Information")
    print("===================")
    print(f"File Path: {file_path}")
    print(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:08X}")
    print(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}")
    print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
    print(f"Timestamp: {pe.FILE_HEADER.TimeDateStamp}")
    print()

    # Sections
    print("Sections")
    print("========")
    for section in pe.sections:
        print(f"Name: {section.Name.decode()}")
        print(f"Virtual Address: 0x{section.VirtualAddress:08X}")
        print(f"Size of Raw Data: {section.SizeOfRawData}")
        print(f"Characteristics: 0x{section.Characteristics:08X}")
        print()

    # Imports
    print("Imports")
    print("=======")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(f"Library: {entry.dll.decode()}")
            for imp in entry.imports:
                if imp.import_by_ordinal:
                    print(f"Ordinal: {str(imp.ordinal)}")
                else:
                    print(f"Function: {imp.name.decode()}")
            print()

    # Exports
    print("Exports")
    print("=======")
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            print(f"Ordinal: {exp.ordinal}")
            print(f"Function: {exp.name.decode()}")
            print()

    # Resources
    print("Resources")
    print("=========")
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                print(f"Resource Type: {resource_type.name.decode()}")
            else:
                print("Resource Type: None")
            for resource_id in resource_type.directory.entries:
                if resource_id.name is not None:
                    print(f"Resource ID: {resource_id.name.decode()}")
                else:
                    print("Resource ID: None")
                for resource_lang in resource_id.directory.entries:
                    print(f"Language: {hex(resource_lang.data.lang)}")
                    print(f"Sublanguage: {hex(resource_lang.data.sublang)}")
                    print(f"Offset: {resource_lang.data.struct.OffsetToData}")
                    print(f"Size: {resource_lang.data.struct.Size}")
                    print()

    # Close the PE file
    pe.close()

def main():
    banner()
    if(len(sys.argv) != 2):
        print("USAGE: winafl_builder.exe <binary>")
        print("AFANX")
        print("channel: https://t.me/k0n70r4")  
        return -1
    
    parse_pe_file(sys.argv[1])

    in_path = input("[ example: -i /path/to/in ] Enter in dir: ")
    out_path = input("[ example: -o /path/to/out ] Enter out dir: ")
    t = input("[ example: -t 1000 ] Enter timeout: ")
    D = input("[ example: -D /path/to/DynamoRIO/bin32 ] Enter path to DynamoRIO: ")
    fuzz_iterations  = input("[ example: -fuzz_iterations  500 ] Enter fuzz fuzz_iterations : ")
    coverage = input("[ example: -coverage_module binary.exe ] Enter coverage module: ")
    target_module = input("[ example: -target_module binary.exe ] Enter target_module: ")
    target_offset = input("[ example: -target_offset 0x01060 ] Enter target_offset: ")
    nargs = input("[ example: -nargs 3 ] Enter nargs: ")
    call_convention  = input("[ example: -call_convention thiscall | sdtcall | cdecl ] Enter nargs: ")
    run_options = input("[ example: @@ ] Enter run options: ")
    
    winafl = ['afl-fuzz.exe']
    winafl.append("-i " + in_path)
    winafl.append("-o " + out_path)
    winafl.append("-t " + t)
    winafl.append("-D " + D + " --")
    winafl.append("-fuzz_iterations  " + fuzz_iterations)
    winafl.append("-coverage_module  " + coverage)
    winafl.append("-target_module " + target_module)
    winafl.append("-target_offset " + target_offset)
    winafl.append("-nargs " + nargs)
    winafl.append("-call_convention " + call_convention + " --")
    winafl.append(sys.argv[1])
    winafl.append(run_options)
    
    command = ""
    for i in winafl:
        command += i + " "
    
    print("[+] Well, done: ",end="")
    
    print(command)
    
    print("AFANX")
    print("channel: https://t.me/k0n70r4")    

if __name__ == "__main__":
    main()