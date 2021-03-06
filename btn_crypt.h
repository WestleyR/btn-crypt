// Created by: WestleyR
// Email: westleyr@nym.hush.com
// Url: https://github.com/WestleyR/btn-crypt
// Last modified date: 2020-12-30
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

  This single file provides a high level basic and fast encryption
  for C programs.

  Key features:
    - Only one dependence; stdio.h
    - Only one source file (this header includes the implementation)
    - Simple easy interface

# How to use

  Define this:
    #define BTN_CRYPT_IMPLEMENTATION

  before including this header file in **one** of your C source
  files to create the implementation.

# Build options

  By adding:
    #define BTN_NO_PRINT_PROG
  (before including this file) there
  will be no progress printed to stdout.


# CHANGELOG

### v1.0.0 - 2020-12-30 (yet to be released)
Init release.


# Contributors
 - WestleyR <westleyr@nym.hush.com>

# TODO:
 - [ ] Should be able to define the tmp dir
 - [ ] Add force flag to decrypt file, like if version missmatch, or data corrupt
 - [x] Should decrypt file while writting to tmp file (right after reading header)
 - [x] Refactor the code
 - [ ] btn_password_from_string() should automaticly get the string size, instead of passing it
 - [ ] Maybe should just use string.h instead of own imitation

*/

#ifndef BTN_CRYPT_INCLUDE_H
#define BTN_CRYPT_INCLUDE_H

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

// btn_encrypt is the main encrypt function. By passing the input file
// path and a password number, the file will be encrypted. The password
// number can be generated from a string by the btn_password_from_string()
// function.
int btn_encrypt(const char* input_file, unsigned int password);

// btn_decrypt is the main decrypting function.
int btn_decrypt(const char* file_name, unsigned int password);

// btn_password_from_string will return a password number from the givin
// string, and the len of the string. Please keep the password short.
unsigned int btn_password_from_string(const char* password_str, int password_len);

//***********************************************
// Internal functions, but you can also use them
//***********************************************

int btn_strcmp(const char* str1, const char* str2);

// btn_strncpy will copy n bytes from src to dest.
void btn_strncpy(void *dest, const void *src, size_t n);

// btn_strcpy will copy src to dest. src should be a null terminated string.
char* btn_strcpy(char* dest, const char* src);

#endif // BTN_CRYPT_INCLUDE_H

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
  FILE* file_to_encrypt_fp = fopen(input_file, "rb");
  if (file_to_encrypt_fp == NULL) {
    perror(input_file);
    return -1;
  }

  // Check if its already encrypted. The file pointer is
  // also returned to its original spot when its complete.
  if (btn_is_file_encrypted(file_to_encrypt_fp) == 0) {
    // File is already encrypted
    fclose(file_to_encrypt_fp);
    fprintf(stderr, "%s(): file is already encrypted\n", __func__);
    return -1;
  }

  btn_header header;

  // Set the BTN magic header and version
  btn_strncpy(header.btn_magic, BTN_MAGIC, 10); // 10 bytes for the header identifier
  btn_strcpy(header.btn_version, BTN_VERSION);
  btn_strcpy(header.btn_message, "");

  // Now save the password key to the header (as unsigend int)
  // this _should not_ be visible in the header.
  header.btn_key = password;

#ifndef BTN_NO_PRINT_PROG
  printf("%s(): encrypting: %s...\n", __func__, input_file);
#endif

  // Now encrypt the file to a tmp file
  FILE* tmp_encrypted_fp = fopen("/tmp/btn_encrypt.btn", "wb");
  if (tmp_encrypted_fp == NULL) {
      return -1;
  }

  // Encrypt the file to a tmp file. Also count the data length.
  long data_len = 0;
  unsigned int ch = fgetc(file_to_encrypt_fp);
  while (ch != EOF) {
      // Check if the password + the char is greater then the unsigend int
      // max value. (I think this is the max value...)
      if (ch + password > 1073741824) {
          fprintf(stderr, "%s: %s(): password too long, exeeded 1073741824.\n", __FILE__, __func__);
          printf("char=%u; psk=%u\n", ch, password);
          return -1;
      }
      ch = ch + password;
      fputc(ch, tmp_encrypted_fp);
      ch = fgetc(file_to_encrypt_fp);
      data_len++;
  }

  fclose(tmp_encrypted_fp);
  fclose(file_to_encrypt_fp);

#ifndef BTN_NO_PRINT_PROG
  printf("%s(): Creating BTN header and data partition...\n", __func__);
#endif

  // Set the encrypted data start and stop
  header.btn_data_start = sizeof(header);
  header.btn_data_end = header.btn_data_start + data_len;

  // Finally, open the final destination file to write
  // the header and encrypted data.
  file_to_encrypt_fp = fopen(input_file, "wb");

  // Write the header
  fwrite(&header, sizeof(header), 1, file_to_encrypt_fp);

  // We do not need to seek to the btn_data_start, since we
  // just finished writting the header to the file, and the
  // file pointer is moved to the currect spot.

  // Open the encrypted tmp data file, and copy it to the final file
  tmp_encrypted_fp = fopen("/tmp/btn_encrypt.btn", "rb");
  unsigned int e = fgetc(tmp_encrypted_fp);
  // Now write the encrypted data
  while (e != EOF) {
    fputc(e, file_to_encrypt_fp);
    e = fgetc(tmp_encrypted_fp);
  }

  fclose(file_to_encrypt_fp);
  fclose(tmp_encrypted_fp);

#ifndef BTN_NO_PRINT_PROG
  printf("%s(): %s successfully encrypted\n", __func__, input_file);
#endif

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

  // Check to see if the file is actrally a btn header/data
  if (btn_strcmp(buffer.btn_magic, BTN_MAGIC) != 0) {
    fprintf(stderr, "%s(): Invalid BTN header. Expecting: %s; got: %s\n", __func__, BTN_MAGIC, buffer.btn_magic);
    return -1;
  }

  // Now check the encryption version
  if (btn_strcmp(buffer.btn_version, BTN_VERSION) != 0) {
    fprintf(stderr, "%s(): Invalid encryption version. Expecting: %s; got: %s\n", __func__, BTN_VERSION, buffer.btn_version);
    return -1;
  }

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

#ifndef BTN_NO_PRINT_PROG
  printf("%s(): Writting and decrypting data...\n", __func__);
#endif

  // Dump and decrypt the encrypted data to a tmp file
  fseek(to_decrypt_fp, buffer.btn_data_start, SEEK_SET);
  int b = fgetc(to_decrypt_fp);
  while (b != EOF) {
    // write to output file
    b = b - password;
    fputc(b, output_stream);
    dump_size++; // Count the size, so we can check later

    // Stop when reached the end of that data block
    if (dump_size > (buffer.btn_data_end - buffer.btn_data_start)) {
      break;
    }
    b = fgetc(to_decrypt_fp);
  }
  fclose(output_stream);
  fclose(to_decrypt_fp);

  // Check the end, make sure its all there.
  if (dump_size != (buffer.btn_data_end - buffer.btn_data_start)) {
    fprintf(stderr, "%s(): ERROR: file missing end! data corrupt. Missing %llu bytes\n", __func__, dump_size - (buffer.btn_data_end - buffer.btn_data_start));
    return -1;
  }

#ifndef BTN_NO_PRINT_PROG
  printf("%s(): Writting output file...\n", __func__);
#endif

  // Now write back the decrypted file back to the original name
  to_decrypt_fp = fopen(file_name, "w");
  FILE* tmp_fp = fopen("/tmp/btn-decrypt.btn", "rb");

  int ch = fgetc(tmp_fp);
  while (ch != EOF) {
    fputc(ch, to_decrypt_fp);
    ch = fgetc(tmp_fp);
  }

  fclose(to_decrypt_fp);
  fclose(tmp_fp);

#ifndef BTN_NO_PRINT_PROG
  printf("%s(): %s successfully decrypted\n", __func__, file_name);
#endif

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

void btn_strncpy(void *dest, const void *src, size_t n) {
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
