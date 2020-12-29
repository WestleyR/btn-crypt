// Created by: WestleyR
// Email: westleyr@nym.hush.com
// Url: https://github.com/WestleyR/btn-crypt
// Last modified date: 2020-12-28
// See: BTN_CRYPT_VERSION for the current version.
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

  This single file provides a high-ish level basic and fast encryption for
  small C programs.

  Key features:
    - Only one dependence, stdio.h
    - Only one source file (this header includes the implementation)
    - Simple easy interface

# How to use

  Define this:
    #define BTN_CRYPT_IMPLEMENTATION
  before including this header file in **one** of your C source
  files to create the implementation.


# CHANGELOG

### v1.0.0 - 2020-12-28 (yet to be released)
Init release.


# Contributors
 - WestleyR <westleyr@nym.hush.com>

# TODO:
 - [ ] Should be able to define the tmp dir

*/

#include <stdio.h>

// The btn_crypt.h version for this file and functions.
#define BTN_CRYPT_VERSION "1.0.0"

// The BTN header
typedef struct {
  char btn_magic[10];
  char btn_version[12];
  char btn_encrypted_date[24];
  char btn_message[24];
  unsigned int btn_key;
  long long btn_data_start;
  long long btn_data_end;
} btn_header;

// The BTN header version, not the same as BTN_CRYPT_VERSION.
const static char BTN_VERSION[] = "1.0.0\0";

// The BTN header identifier, this should never change
const static char BTN_MAGIC[] = "BTN_CRYPT\0";

//****************
// Crypt functions
//****************
int btn_encrypt(const char* input_file, unsigned int password);
int btn_decrypt(const char* file_name, unsigned int password);
unsigned int btn_password_from_string(const char* password_str, int password_len);

//***********************************************
// Internal functions, but you can also use them
//***********************************************
int btn_strcmp(const char* str1, const char* str2);
void btn_memcpy(void *dest, const void *src, size_t n);
// btn_strcpy will copy src to dest. src should be a null terminated string.
char* btn_strcpy(char* dest, const char* src);

//*******************
// The implementation
//*******************
#ifdef BTN_CRYPT_IMPLEMENTATION

unsigned int btn_password_from_string(const char* password_str, int password_len) {
  unsigned int ret = 0;

  for (int i = 0; i < password_len; i++) {
    ret = (ret * 10) + password_str[i];
  }

  return ret;
}

int btn_read_header(btn_header* header, FILE* btn_fp) {
  if (btn_fp == NULL) {
    fprintf(stderr, "%s(): non-valid image pointer\n", __func__);
    return -1;
  }

  // Get file poststion before reading, so we can put it back there.
  long int before_p = ftell(btn_fp);

  fread(&*header, sizeof(*header), 1, btn_fp);

  // Return it to the original spot
  fseek(btn_fp, before_p, SEEK_SET);

  return 0;
}

// btn_is_file_encrypted checks for the btn header, if valid, then
// the file is encrypted.
int btn_is_file_encrypted(FILE* file_fp) {
  if (file_fp == NULL) {
    return -1;
  }

  btn_header header;
  btn_read_header(&header, file_fp);

  if (btn_strcmp(header.btn_magic, BTN_MAGIC) == 0) {
    // Valid header magic
    return 0;
  }

  return 1;
}

int btn_encrypt(const char* input_file, unsigned int password) {
  // First check if the file is already encrypted
  FILE* input_fp = fopen(input_file, "rb");
  if (input_fp == NULL) {
    perror(__func__);
    return -1;
  }
  if (btn_is_file_encrypted(input_fp) == 0) {
    // File is already encrypted
    fclose(input_fp);
    fprintf(stderr, "%s(): file is already encrypted\n", __func__);
    return -1;
  }
  fclose(input_fp);

  btn_header header;

  // Set the BTN magic header and version
  btn_memcpy(header.btn_magic, BTN_MAGIC, 10); // 10 bytes for the header identifier
  btn_strcpy(header.btn_version, BTN_VERSION);
  btn_strcpy(header.btn_message, "");

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
      // Check if the password + the char is grader then the unsigend int
      // max value. (I think this is the max value...)
      if (ch + password > 1073741824) {
          fprintf(stderr, "%s: %s(): password too long, exeeded 1073741824.\n", __FILE__, __func__);
          printf("char=%u; psk=%u\n", ch, password);
          return -1;
      }
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

// btn_decrypt is the main decrypt function.
int btn_decrypt(const char* file_name, unsigned int password) {
  // First, open the file to decrypt
  FILE* to_decrypt_fp = fopen(file_name, "rb");
  if (to_decrypt_fp == NULL) {
    return 1;
  }

  // Read the header
  btn_header buffer;
  fread(&buffer, sizeof(buffer), 1, to_decrypt_fp);

  // TODO: should check the header before decrypting it

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

  printf("Writting data to output...\n");

  // Print the image data
  fseek(to_decrypt_fp, buffer.btn_data_start, SEEK_SET);
  int b = fgetc(to_decrypt_fp);
  while (b != EOF) {
    // write to output file
    fputc(b, output_stream);
    dump_size++; // Count the size, so we can check later

    // Stop when reached the end of that data block
    if (dump_size > (buffer.btn_data_end - buffer.btn_data_start)) {
      break;
    }
    b = fgetc(to_decrypt_fp);
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

  printf("Decrypting data...\n");

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

//*******************
// Internal functions
//*******************

size_t btn_strlen(const char* str) {
  const char *c;
  for (c = str; *c; ++c);
  return (c - str);
}

int btn_strcmp(const char* str1, const char* str2) {
  while(*str1 && (*str1 == *str2)) {
    str1++;
    str2++;
  }
  return *(const unsigned char*)str1 - *(const unsigned char*)str2;
}

void btn_memcpy(void *dest, const void *src, size_t n) {
  char *csrc = (char *)src;
  char *cdest = (char *)dest;

  for (int i = 0; i < n; i++) {
    cdest[i] = csrc[i];
  }
}

char* btn_strcpy(char* dest, const char* src) {
  if (dest == NULL) {
    return NULL;
  }
  char *ptr = dest;

  while (*src != '\0') {
    *dest = *src;
    dest++;
    src++;
  }

  *dest = '\0';

  return ptr;
}

#endif

// vim: tabstop=2 shiftwidth=2 expandtab autoindent softtabstop=0
