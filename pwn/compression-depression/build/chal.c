#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

int get_opt() {
    printf("[Menu]\n");
    printf("0. Input Buffer\n");
    printf("1. Compress\n");
    printf("2. Decompress\n");
    printf("3. Display Buffer\n");
    printf(">");
    char c;
    do {
        c = getc(stdin);
    } while (!isdigit(c));
    return  c - '0';
}

int run_len_compress(char *buf, int len) {
    char workspace[512];
    memcpy(workspace, buf, len);
    char curr = '\0';
    int non_run_start = 0, curr_len = 0, run_len = 0, j = 0;
    for (int i = 0; i < len; i++) {
        if (i == 0 || buf[i] != curr) {
            if (run_len > 1) {
                buf[j++] = (1 << 7) | (char)run_len;
                buf[j++] = curr;
                non_run_start = i;
            }
            curr = workspace[i];
            curr_len++;
            run_len = 1;
        } else {
            if (curr_len > 1) {
                buf[j++] = (char)(curr_len - 1);
                if (non_run_start + curr_len - 1 > len) {
                    goto err_c;
                }
                for (int k = non_run_start; k < non_run_start + curr_len - 1; k++) {
                    buf[j++] = workspace[k];
                }
            }
            run_len++;
            curr_len = 0;
        }
    }
    
    if (curr_len > 0) {
        buf[j++] = (char)curr_len;
        if (non_run_start + curr_len > len) {
            goto err_c;
        }
        for (int k = non_run_start; k < non_run_start + curr_len; k++) {
            buf[j++] = workspace[k];
        }
    } else {
        buf[j++] = (1 << 7) | (char)run_len;
        buf[j++] = curr;
    }
    return j;
err_c:
    printf("Implementation Error Detected!\n");
    return 0;
}

int run_len_decompress(char *buf, int len) {
    char workspace[512];
    int i = 0, j = 0;
    while (i < len) {
        int is_run = buf[i] >> 7;
        int curr_len = buf[i] & 127;
        if (j + curr_len > 512) {
            printf("Out of Space!\n");
            return 0;
        }
        i++;
        if (i >= len) {
            goto err_d;
        }
        if (is_run) {
            for (int k = 0; k < curr_len; k++) {
                workspace[j++] = buf[i];
            }
            i++;
        } else {
            if (i + curr_len - 1 >= len) {
                goto err_d;
            }
            for (int k = 0; k < curr_len; k++) {
                workspace[j++] = buf[i++];
            }
        }
    }
    memcpy(buf, workspace, j);
    return j;
err_d:
    printf("Corruption Detected!\n");
    return 0;
}

int main(int argc, const char *argv[]) {
    printf("Run-length Compression Utils v1.337\n");
    char buf[512];
    int read_len = 0;
    int len = 0;
    while (1) {
        read_len = get_opt();
        switch (read_len) {
            case 0:
                read_len = 0;
                printf("New Length:");
                scanf("%d%*c", &read_len);
                if (read_len <= 0 || read_len > 512) {
                    printf("Bad Length: %d\n", read_len);
                    break;
                }
                len = fread(buf, sizeof(char), read_len, stdin);
                if (len == 0) {
                    printf("Read Failed\n");
                    exit(0);
                }
                break;
            case 1:
                len = run_len_compress(buf, len);
                break;
            case 2:
                len = run_len_decompress(buf, len);
                break;
            case 3:
                printf("Buffer (Length=%d):", len);
                fwrite(buf, sizeof(char), len, stdout);
                printf("\n");
                break;
            default:
                goto end;
        }
        
    }
end:
    printf("Goodbye!\n");
    return 0;
}