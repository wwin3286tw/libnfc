#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nfc/nfc.h>
#include <unistd.h>
#include "getopt.h"
#include "mifare.h"

#define MAX_KEYS 256

typedef enum {
    RW_READ,
    RW_WRITE
} rw_mode;

void read_keys_from_file(const char* filename, uint8_t keys[MAX_KEYS][6], size_t* num_keys);
void print_usage(char* argv[]);

void authenticate_and_write_block(nfc_device* device, nfc_modulation nm, nfc_context* context, uint8_t block_number, char key_type, uint8_t keys[][6], size_t num_keys, const uint8_t* data_to_write, int quiet_mode);
void authenticate_and_read_block(nfc_device* device, nfc_modulation nm, nfc_context* context, uint8_t block_number, char key_type, uint8_t keys[][6], size_t num_keys, int quiet_mode, int dump_all);

int main(int argc, char* argv[]) {
    nfc_device* device = NULL;
    nfc_context* context;
    nfc_target target;

    int opt;
    uint8_t block_number = 0;
    char key_type = 'A';
    char* key_text = NULL;
    char* key_file = NULL;
    uint8_t keys[MAX_KEYS][6];
    size_t num_keys = 0;
    int quiet_mode = 0, dump_all = 0;
    rw_mode mode = RW_READ;
    uint8_t write_data[16] = { 0 };
    int write_data_provided = 0;

    static struct option long_options[] = {
        {"block_number", required_argument, 0, 'b'},
        {"key_type", required_argument, 0, 't'},
        {"key_text", required_argument, 0, 'k'},
        {"key_file", required_argument, 0, 'f'},
        {"quiet_mode", no_argument, 0, 'q'},
        {"dump_all", no_argument, 0, 'd'},
        {"rw_mode", required_argument, 0, 'r'},
        {"write_data", required_argument, 0, 'w'},
        {0, 0, 0, 0} };


    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "b:t:k:f:qdm:r:w:", long_options, &option_index)) != -1) {
        switch (opt) {
        case 'b':
            block_number = atoi(optarg);
            break;
        case 't':
            key_type = optarg[0];
            break;
        case 'k':
            key_text = optarg;
            break;
        case 'f':
            key_file = optarg;
            break;
        case 'q':
            quiet_mode = 1;
            break;
        case 'd':
            dump_all = 1;
            break;
        case 'r':
            if (strcmp(optarg, "w") == 0) {
                mode = RW_WRITE;
            }
            else if (strcmp(optarg, "r") == 0) {
                mode = RW_READ;
            }
            else {
                print_usage(argv);
                return 1;
            }
            break;
        case 'w':
            if (strlen(optarg) != 32 || sscanf(optarg, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx", &write_data[0], &write_data[1], &write_data[2], &write_data[3], &write_data[4], &write_data[5], &write_data[6], &write_data[7], &write_data[8], &write_data[9], &write_data[10], &write_data[11], &write_data[12], &write_data[13], &write_data[14], &write_data[15]) != 16) {
                fprintf(stderr, "Invalid write data. Must be 32 hex characters long.\n");
                return 1;
            }
            write_data_provided = 1;
            break;
        default:
            print_usage(argv);
            return 1;
        }
    }
    if (!key_text && !key_file) {
        printf("Error: No key specified. Please provide a key using --key_text or --key_file option.\n");
        print_usage(argv);
        exit(EXIT_FAILURE);
    }

    if (mode == RW_WRITE && dump_all) {
        printf("Error: rw_mode == write and dump_all have been provided. The --dump_all option only works when the --rw_mode is set to read.\n");
        exit(EXIT_FAILURE);
    }
    if (block_number && dump_all) {
        printf("Error: Both block_number and dump_all are provided. Please choose only one option.\n");
        exit(EXIT_FAILURE);
    }

    if (key_text && key_file) {
        printf("Error: Both key_text and key_file are provided. Please choose only one option.\n");
        exit(EXIT_FAILURE);
    }
    if (key_text) {
        if (strlen(key_text) != 12) {
            printf("Error: Invalid key length. A key must be exactly 12 hexadecimal characters.\n");
            exit(EXIT_FAILURE);
        }
        sscanf(key_text, "%02x%02x%02x%02x%02x%02x", &keys[0][0], &keys[0][1], &keys[0][2], &keys[0][3], &keys[0][4], &keys[0][5]);
        num_keys = 1;
    }
    else if(key_file) {
        read_keys_from_file(key_file, keys, &num_keys);
    }
    else {
        print_usage(argv);
        return 1;
    }

    nfc_init(&context);
    if (context == NULL) {
        fprintf(stderr, "Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }

    device = nfc_open(context, NULL);
    if (device == NULL) {
        fprintf(stderr, "Unable to open NFC device.\n");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    nfc_modulation nm = {
        .nmt = NMT_ISO14443A,
        .nbr = NBR_106 };

    if (nfc_initiator_select_passive_target(device, nm, NULL, 0, &target) <= 0) {
        fprintf(stderr, "Unable to find NFC target.\n");
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    if (mode == RW_READ) {
        if (dump_all) {
            for (uint8_t i = 0; i < 64; i++) {
                authenticate_and_read_block(device, nm, context, i, key_type, keys, num_keys, quiet_mode, dump_all);
            }
        }
        else {
            authenticate_and_read_block(device, nm, context, block_number, key_type, keys, num_keys, quiet_mode, dump_all);
        }
    }
    else if (mode == RW_WRITE) {
        if (!write_data_provided) {
            fprintf(stderr, "No write data provided.\n");
            nfc_close(device);
            nfc_exit(context);
            exit(EXIT_FAILURE);
        }
        authenticate_and_write_block(device, nm, context, block_number, key_type, keys, num_keys, write_data,  quiet_mode);
    }
    else {
        fprintf(stderr, "Invalid mode.\n");
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    nfc_close(device);
    nfc_exit(context);
    return 0;
}

void authenticate_and_write_block(nfc_device* device, nfc_modulation nm, nfc_context* context, uint8_t block_number, char key_type, uint8_t keys[][6], size_t num_keys, const uint8_t* data_to_write, int quiet_mode) {
    nfc_target target;
    bool authenticated = false;
    for (size_t i = 0; i < num_keys; ++i) {
        nfc_initiator_select_passive_target(device, nm, NULL, 0, &target);
        mifare_param mp_auth;
        memcpy(mp_auth.mpa.abtKey, keys[i], 6);
        memcpy(mp_auth.mpa.abtAuthUid, target.nti.nai.abtUid, 4);
        if (quiet_mode == 0) {
            printf("key #%zu: %02x%02x%02x%02x%02x%02x\n", i + 1, keys[i][0], keys[i][1], keys[i][2], keys[i][3], keys[i][4], keys[i][5]);
        }
        if (key_type == 'A') {
            if (nfc_initiator_mifare_cmd(device, MC_AUTH_A, block_number, &mp_auth)) {
                authenticated = true;
                break;
            }
        }
        else if (key_type == 'B') {
            if (nfc_initiator_mifare_cmd(device, MC_AUTH_B, block_number, &mp_auth)) {
                authenticated = true;
                break;
            }
        }
        else {
            printf("Error: Invalid key type. Valid options are 'A' or 'B'.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (!authenticated) {
        printf("Authentication for block %d failed\n", block_number);
        return;
    }

    mifare_param mp_write;
    memcpy(mp_write.mpd.abtData, data_to_write, 16);
    if (!nfc_initiator_mifare_cmd(device, MC_WRITE, block_number, &mp_write)) {
        fprintf(stderr, "Writing block %d failed\n", block_number);
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    if (quiet_mode == 0) {
        printf("Successfully wrote block %d: ", block_number);
        for (int i = 0; i < sizeof(mp_write.mpd.abtData); i++) {
            printf("%02x ", mp_write.mpd.abtData[i]);
        }
        printf("\n");
    }
}
void authenticate_and_read_block(nfc_device* device, nfc_modulation nm, nfc_context* context, uint8_t block_number, char key_type, uint8_t keys[][6], size_t num_keys, int quiet_mode, int dump_all) {
    nfc_target target;
    bool authenticated = false;
    for (size_t i = 0; i < num_keys; ++i) {
        nfc_initiator_select_passive_target(device, nm, NULL, 0, &target);
        mifare_param mp_auth;
        memcpy(mp_auth.mpa.abtKey, keys[i], 6);
        memcpy(mp_auth.mpa.abtAuthUid, target.nti.nai.abtUid, 4);
        if (quiet_mode == 0 ) {
            printf("key #%zu: %02x%02x%02x%02x%02x%02x\n", i + 1, keys[i][0], keys[i][1], keys[i][2], keys[i][3], keys[i][4], keys[i][5]);
        }
        if (key_type == 'A') {
            if (nfc_initiator_mifare_cmd(device, MC_AUTH_A, block_number, &mp_auth)) {
                authenticated = true;
                break;
            }
        }
        else if (key_type == 'B') {
            if (nfc_initiator_mifare_cmd(device, MC_AUTH_B, block_number, &mp_auth)) {
                authenticated = true;
                break;
            }
        }
        else {
            printf("Error: Invalid key type. Valid options are 'A' or 'B'.\n");
            exit(EXIT_FAILURE);
        }
    }

    if (!authenticated) {
        printf("Authentication for block %d failed\n", block_number);
        return;
    }

    mifare_param mp_read;
    if (!nfc_initiator_mifare_cmd(device, MC_READ, block_number, &mp_read)) {
        fprintf(stderr, "Reading block %d failed\n", block_number);
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }
    if (quiet_mode == 0 || dump_all == 1)  {
        printf("%02d:", block_number);
    }
    for (int i = 0; i < sizeof(mp_read.mpd.abtData); i++) {
        printf("%02x ", mp_read.mpd.abtData[i]);
    }
    printf("\n");
}
void read_keys_from_file(const char* filename, uint8_t keys[MAX_KEYS][6], size_t* num_keys) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    char line[13];
    size_t count = 0;
    while (fgets(line, sizeof(line), file) && count < MAX_KEYS) {
        if (strlen(line) >= 12) {
            sscanf(line, "%02x%02x%02x%02x%02x%02x", &keys[count][0], &keys[count][1], &keys[count][2], &keys[count][3], &keys[count][4], &keys[count][5]);
            count++;
        }
    }

    fclose(file);
    *num_keys = count;
}
void print_usage(char* argv[]) {
    printf("Usage: %s\n"
        "\t--block_number BLOCK_NUMBER : The block number to read or write. Required.\n"
        "\t[--rw_mode r|w] : The read/write mode. Optional. Default is r\n"
        "\t[--key_type KEY_TYPE] : The authentication key type, 'A' or 'B'. Default is 'A'.\n"
        "\t[--key_text KEY_TEXT | --key_file KEY_FILE] : The authentication key in hex format (12 characters) or a file containing multiple keys (one key per line). Either one of these options must be provided. No default value.\n"
        "\t[--write_data DATA] : The data to be written in hex format (32 characters). Required in write mode (rw_mode=w).\n"
        "\t[--quiet_mode] : Do not print out the key or data. Optional.\n"
        "\t[--dump_all] : The [--dump_all] option can only be used in read mode [--rw_mode=r], and must be used with the [--block_number] option. It allows for dumping all blocks.\n"
        "Example:\n"
        "* Write: nfc-mfblock.exe --key_text FFFFFFFFFFFF --rw_mode w --write_data 000000FFFF0000000000000000000000 --block_number 1 --key_type B \n"
        "* Write with keyfile: nfc-mfblock.exe --key_file test.key --rw_mode w --write_data 000000FFFF0000000000000000000000 --block_number 1 --key_type B\n"
        "* Read: nfc-mfblock.exe --key_text FFFFFFFFFFFF  --rw_mode r --block_number 1 --key_type A\n"
        "* Read with keyfile: nfc-mfblock.exe --key_file test.key  --rw_mode r --block_number 1 --key_type A", argv[0]);
}