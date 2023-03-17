#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nfc/nfc.h>
#include <unistd.h>
#include "getopt.h"
#include "mifare.h"

#define MAX_KEYS 256

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

int main(int argc, char* argv[]) {
    nfc_device* device = NULL;
    nfc_context* context;
    nfc_target target;

    // Parse command line options
    int opt;
    uint8_t block_number = 0;
    char key_type = 'A';
    char* key_text = NULL;
    char* key_file = NULL;
    uint8_t keys[MAX_KEYS][6];
    size_t num_keys = 0;

    static struct option long_options[] = {
        {"block_number", required_argument, 0, 'b'},
        {"key_type", required_argument, 0, 't'},
        {"key_text", required_argument, 0, 'k'},
        {"key_file", required_argument, 0, 'f'},
        {0, 0, 0, 0}
    };

    int option_index = 0;
    while ((opt = getopt_long(argc, argv, "b:t:k:f:", long_options, &option_index)) != -1) {
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
        default:
            printf("Usage: %s --block_number BLOCK_NUMBER --key_type KEY_TYPE [--key_text KEY_TEXT | --key_file KEY_FILE]\n", argv[0]);
            exit(EXIT_FAILURE);
        }
    }

    if (!key_text && !key_file) {
        printf("Error: No key specified. Please provide a key using --key_text or --key_file option.\n");
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

    //printf("Target detected!\n");

    bool authenticated = false;
    for (size_t i = 0; i < num_keys; ++i) {
        nfc_initiator_select_passive_target(device, nm, NULL, 0, &target);
        mifare_param mp_auth;
        memcpy(mp_auth.mpa.abtKey, keys[i], 6);
        memcpy(mp_auth.mpa.abtAuthUid, target.nti.nai.abtUid, 4);
        printf("Trying key #%zu: %02x%02x%02x%02x%02x%02x\n", i + 1, keys[i][0], keys[i][1], keys[i][2], keys[i][3], keys[i][4], keys[i][5]);
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
        fprintf(stderr, "Authentication failed for all keys.\n");
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    mifare_param mp_read;
    if (!nfc_initiator_mifare_cmd(device, MC_READ, block_number, &mp_read)) {
        fprintf(stderr, "Reading block failed\n");
        nfc_close(device);
        nfc_exit(context);
        exit(EXIT_FAILURE);
    }

    printf("Block %d data: ", block_number);
    for (int i = 0; i < sizeof(mp_read.mpd.abtData); i++) {
        printf("%02x ", mp_read.mpd.abtData[i]);
    }
    printf("\n");

    nfc_close(device);
    nfc_exit(context);
    exit(EXIT_SUCCESS);
}