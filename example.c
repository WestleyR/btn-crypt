// Created by: WestleyR
// Email: westleyr@nym.hush.com
// Url: https://github.com/WestleyR/btn-crypt
// Last modified date: 2020-12-27
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

// Compile this test example by:
//   gcc example.c
//
// Make sure you create "hello.txt" before running.

#define BTN_CRYPT_IMPLEMENTATION
#include "btn_crypt.h"

int main(int argc, char** argv) {

  unsigned int psk = btn_password_from_string("hello", 5);
  btn_encrypt("hello.txt", psk);

  return(0);
}

// vim: set autoindent set tabstop=2 softtabstop=0 expandtab shiftwidth=2 smarttab

