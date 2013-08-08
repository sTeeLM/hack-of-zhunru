#ifndef __BNAC_ENC_H__
#define __BNAC_ENC_H__
#include <string>
	bool enc_buffer(void * buffer, size_t real_len, size_t total_len, int cipher_num);
	bool dec_buffer(void * buffer, size_t real_len, size_t total_len, int cipher_num);
	bool rsa_enc_pass(const std::string & pass, std::string & enc_pass);
#endif
