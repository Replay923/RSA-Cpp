#pragma once

char * OpenSSL_Base64Encode(const char * input, int length, bool with_new_line);
char * OpenSSL_Base64Decode(const char * input, int length, bool with_new_line);