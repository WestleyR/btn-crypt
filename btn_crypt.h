// Created by: WestleyR
// Email: westleyr@nym.hush.com
// Url: https://github.com/WestleyR/btn-crypt
// Last modified date: 2020-12-25
//
// This file is licensed under the terms of
//
// The Clear BSD License
//
// Copyright (c) 2020 WestleyR
// All rights reserved.
//
// This software is licensed under a Clear BSD License.
//

/*

  BTN crypt - better-than-nothing encryption/decryption

  This file provides a higher level basic and fast encryption for
  small C programs.

# How to use

  Define this:
    #define BTN_CRYPT_IMPLEMENTATION
  before including this in **one** of your C source files to create the implementation.


# CHANGELOG

### v1.0.0 - 2020-12-25 (yet to be released)
Init release.

*/

/*
 * TODO LIST:
 *  - [ ] should check if the file is already encrypted before encrypting it
 *
 */

#include <stdio.h>

// The BTN header
typedef struct {
  char btn_magic[9];
  char btn_version[12];
  char btn_encrypted_date[24];
  char btn_message[24];
  unsigned int btn_key;
  long long btn_data_start;
  long long btn_data_end;
} btn_header;

const static char BTN_MAGIC[] = "BTN_CRYPT";
const static char BTN_VERSION[] = "0.1.0";

int btn_encrypt(const char* input_file, unsigned int password);
int btn_decrypt(const char* file_name, unsigned int password);
unsigned int btn_password_from_string(const char* password_str, int password_len);

#ifdef BTN_CRYPT_IMPLEMENTATION
// The implementation

unsigned int btn_password_from_string(const char* password_str, int password_len) {
  unsigned int ret = 0;

  for (int i = 0; i < password_len; i++) {
    ret += password_str[i];
  }

  return ret;
}

int btn_encrypt(const char* input_file, unsigned int password) {

  btn_header header;

  // Set the BTN magic header and version
  memcpy(header.btn_magic, BTN_MAGIC, 9); // 9 bytes for the header identifier
  strcpy(header.btn_version, BTN_VERSION);
  strcpy(header.btn_message, "");

  // Now save the password key to the header (as unsigend int)
  // this _should not_ be visible in the header.
  header.btn_key = password;

  // Now encrypt the file to a tmp file
  FILE* to_encrypt_fp = fopen(input_file, "r");
  if (to_encrypt_fp == NULL) {
      return -1;
  }

  FILE* tmp_fp = fopen("/tmp/btn_encrypt.btn", "wb");
  if (tmp_fp == NULL) {
      return -1;
  }

  // Encrypt the file to a tmp file
  unsigned int ch = fgetc(to_encrypt_fp);
  while (ch != EOF) {
      ch = ch + password;
      fputc(ch, tmp_fp);
      ch = fgetc(to_encrypt_fp);
  }

  fclose(tmp_fp);
  fclose(to_encrypt_fp);

  // Now read the data len of the encrypted data
  // TODO: this should be called the input file fp
  FILE* thumbnail_fp = fopen("/tmp/btn_encrypt.btn", "rb");

  long data_len = 0;
  // Get file poststion before reading, so we can put it back there.
  // Now read the file
  int c = fgetc(thumbnail_fp);
  while (c != EOF) {
    data_len++;
    c = fgetc(thumbnail_fp);
  }
  fclose(thumbnail_fp);

  // Set the encrypted data start and stop
  header.btn_data_start = sizeof(header);
  header.btn_data_end = header.btn_data_start + data_len;

  FILE* btn_file = fopen(input_file, "wb");

  // Write the header
  fwrite(&header, sizeof(header), 1, btn_file);

  // Now write the encrypted data
  fseek(btn_file, header.btn_data_start, SEEK_SET);
  FILE* encrypted_data_fp = fopen("/tmp/btn_encrypt.btn", "rb");
  int e = fgetc(encrypted_data_fp);
  while (e != EOF) {
    fputc(e, btn_file);
    e = fgetc(encrypted_data_fp);
  }

  fclose(btn_file);

  printf("Done\n");

  return 0;
}

int btn_decrypt(const char* file_name, unsigned int password) {
  FILE* to_decrypt_fp = fopen(file_name, "rb");
  if (to_decrypt_fp == NULL) {
    return 1;
  }

  btn_header buffer;
  fread(&buffer, sizeof(buffer), 1, to_decrypt_fp);

  // Check if theres data before
  if ((buffer.btn_data_end - buffer.btn_data_start) == 0) {
    return -1; // Since it is empty
  }

  // Check if the supplied password int matches the header key
  if (password != buffer.btn_key) {
    fprintf(stderr, "%s: %s(): invalid password\n", __FILE__, __func__);
    return -1;
  }

  long int dump_size = 0;

  // Open the outout stream
  FILE* output_stream = fopen("/tmp/btn-decrypt.btn", "wb");

  // Print the image data
  fseek(to_decrypt_fp, buffer.btn_data_start, SEEK_SET);
  int b = fgetc(to_decrypt_fp);
  while (b != EOF) {
    // write to output file
    fputc(b, output_stream);
    dump_size++; // Count the size, so we can check later
    b = fgetc(to_decrypt_fp);

    // Stop when reached the end of that data block
    if (ftell(to_decrypt_fp) > buffer.btn_data_end) {
      break;
    }
  }
  fclose(output_stream);

  // Check the end, make sure its all there.
  if (dump_size != (buffer.btn_data_end - buffer.btn_data_start)) {
    printf("%ld -> %llu\n", dump_size, buffer.btn_data_end - buffer.btn_data_start);
    printf("ERROR: file missing end! data corrupt\n");
  }

  fclose(to_decrypt_fp);


  to_decrypt_fp = fopen("/tmp/btn-decrypt.btn", "rb");
  if (to_decrypt_fp == NULL) {
    return 0;
  }

  FILE* tmp_fp = fopen("/tmp/tmp.txt", "w");
  if (tmp_fp == NULL) {
    return -1;
  }

  int ch = fgetc(to_decrypt_fp);
  while (ch != EOF) {
    ch = ch - password;
    fputc(ch, tmp_fp);
    ch = fgetc(to_decrypt_fp);
  }

  fclose(to_decrypt_fp);
  fclose(tmp_fp);


  // Now write back the decrypted file back to the original name
  to_decrypt_fp = fopen(file_name, "w");
  tmp_fp = fopen("/tmp/tmp.txt", "r");

  ch = fgetc(tmp_fp);
  while (ch != EOF) {
    fputc(ch, to_decrypt_fp);
    ch = fgetc(tmp_fp);
  }

  fclose(to_decrypt_fp);
  fclose(tmp_fp);

  return 0;
}

#endif

// vim: tabstop=2 shiftwidth=2 expandtab autoindent softtabstop=0
