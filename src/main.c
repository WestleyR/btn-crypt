// Created by: WestleyR
// Email: westleyr@nym.hush.com
// Url: https://github.com/WestleyR/btn-crypt
// Last modified date: 2020-12-28
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>

#define BTN_CRYPT_IMPLEMENTATION
#include "btn_crypt.h"

int main(int argc, char** argv) {


  int encrypt_file = 0;
  int decrypt_file = 0;
  char* password;

  int opt = 0;

  static struct option long_options[] = {
    {"password",    required_argument, 0, 'p'},
    {"encrypt",     no_argument,       0, 'e'},
    {"decrypt",     no_argument,       0, 'd'},
    {"help",        no_argument,       0, 'h'},
    {"version",     no_argument,       0, 'V'},
    {NULL, 0, 0, 0}
  };

  while ((opt = getopt_long(argc, argv, "p:edVh", long_options, 0)) != -1) {
    switch (opt) {
      case 'e':
	    encrypt_file = 1;
        break;

      case 'd':
	    decrypt_file = 1;
        break;

      case 'p':
        password = (char*) malloc(strlen(optarg) * sizeof(char) + 2);
        strcpy(password, optarg);
        break;

      case 'V':
        //print_version();
        return(0);

      case 'h':
        //print_usage(argv[0]);
        return(0);

      default:
        return(22);
    }
  }

  // Make sure all the options are valid
  int i = encrypt_file + decrypt_file;
  if (i == 0) {
    printf("No action\n");
    return 1;
  }
  if (i > 1) {
    printf("Too many actions\n");
    return 1;
  }

  // Loop throuht the extra arguments
  if (optind < argc) {
    // Only can support one image right now...
    if ((argc - optind) > 1) {
      printf("Too many source files\n");
      return 1;
    }

	if (password == NULL) {
	  fprintf(stderr, "%s: password is empty\n", argv[0]);
	  return 1;
    }

	unsigned int password_int = btn_password_from_string(password, strlen(password));
	if (password_int == 0) {
	  // Failed to generate the password
	  fprintf(stderr, "%s: %s(): Failed to generate a password.\n", __FILE__, __func__);
	  return 1;
    }
	//printf("HELLOWLRD: %u\n", password_int);

    for (int i = optind; i < argc; i++) {
	  if (encrypt_file == 1) {
	    if (btn_encrypt(argv[i], password_int) != 0) {
            printf("%s: %s failed to encrypt encrypted\n", argv[0], argv[i]);
        }
	  } else if (decrypt_file == 1) {
	    if (btn_decrypt(argv[i], password_int) != 0) {
            printf("%s: %s failed to decrypted\n", argv[0], argv[i]);
        }
	  }
    }
  } else {
    printf("No files passed\n");
    return 1;
  }

  //btn_encrypt(file_name, 240);

  return(0);
}

// vim: set autoindent set tabstop=2 softtabstop=0 expandtab shiftwidth=2 smarttab

