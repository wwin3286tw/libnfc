#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nfc/nfc.h>
#include <unistd.h>
#include "getopt.h"
#include "mifare.h"

#define MAX_KEYS 256

void read_keys_from_file(const char* filename, uint8_t keys[MAX_KEYS][6], size_t* num_keys);
void print_usage(char* argv[]);
void authenticate_and_read_block(nfc_device* device, nfc_modulation nm, nfc_context* context, uint8_t block_number, char key_type, uint8_t keys[][6], size_t num_keys, int quiet_mode);

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

    static struct option long_options[] = {
        {"block_number", required_argument, 0, 'b'},
        {"key_type", required_argument, 0, 't'},
        {"key_text", required_argument, 0, 'k'},
        {"key_file", required_argument, 0, 'f'},
        {"quiet_mode", no_argument, 0, 'q'},
        {"dump_all", no_argument, 0, 'd'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "b:t:k:f:qd", long_options, &option_index)) != -1) {
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
        default:
            print_usage(argv);
            exit(EXIT_FAILURE);
        }
    }

    if (!key_text && !key_file) {
        printf("Error: No key specified. Please provide a key using --key_text or --key_file option.\n");
        print_usage(argv);
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
    else {
        read_keys_from_file(key_file, keys, &num_keys);
    }

    nfc_init(&context);
    if (context == NULL) {
        printf("Unable to init libnfc (malloc)\n");
        exit(EXIT_FAILURE);
    }

    device = nfc_open(context, NULL);

    if (device == NULL) {
        printf("ERROR: %s\n", "Unable to open NFC device.");
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    if (nfc_initiator_init(device) < 0) {
        nfc_perror(device, "nfc_initiator_init");
        exit(EXIT_FAILURE);
    }

    nfc_modulation nm = {
        .nmt = NMT_ISO14443A,
        .nbr = NBR_106,
    };

    if (nfc_initiator_select_passive_target(device, nm, NULL, 0, &target) <= 0) {
        printf("Error: no target found.\n");
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    if (dump_all) {
        for (int current_block = 0; current_block < 64; current_block++) {
            authenticate_and_read_block(device, nm, context, current_block, key_type, keys, num_keys, quiet_mode);
        }
    }
    else {
        authenticate_and_read_block(device, nm, context, block_number, key_type, keys, num_keys, quiet_mode);
    }

    nfc_close(device);
    nfc_exit(context);
    exit(EXIT_SUCCESS);
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
    printf("Usage: %s --block_number BLOCK_NUMBER --key_type KEY_TYPE [--key_text KEY_TEXT | --key_file KEY_FILE] [--quiet_mode] [--dump_all]\n", argv[0]);
}

void authenticate_and_read_block(nfc_device* device, nfc_modulation nm, nfc_context* context, uint8_t block_number, char key_type, uint8_t keys[][6], size_t num_keys, int quiet_mode) {
    nfc_target target;
    bool authenticated = false;
    for (size_t i = 0; i < num_keys; ++i) {
        nfc_initiator_select_passive_target(device, nm, NULL, 0, &target);
        mifare_param mp_auth;
        memcpy(mp_auth.mpa.abtKey, keys[i], 6);
        memcpy(mp_auth.mpa.abtAuthUid, target.nti.nai.abtUid, 4);
        if (quiet_mode == 0){
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
    if (quiet_mode == 0) {
        printf("%02d:", block_number);
    }
    for (int i = 0; i < sizeof(mp_read.mpd.abtData); i++) {
        printf("%02x ", mp_read.mpd.abtData[i]);
    }
    printf("\n");
}
