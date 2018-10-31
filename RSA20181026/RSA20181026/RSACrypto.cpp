#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <vector>
#include <algorithm>

#include "RSACrypto.h"

RSACrypto::~RSACrypto()
{
	Release();
}

bool  RSACrypto::InitPrivateRSA()
{
	BIO* keybio = nullptr;

	keybio = BIO_new_mem_buf((char*)m_strPrivateKey.data(), -1);
	if (keybio == NULL)
	{
		printf("Failed to create private key BIO\n");
		return false;
	}

	m_PrivatekeyRsa = PEM_read_bio_RSAPrivateKey(keybio, &m_PrivatekeyRsa, NULL, NULL);
	if (!m_PrivatekeyRsa)
	{
		printf("Failed to create private RSA\n");
		BIO_set_close(keybio, BIO_CLOSE);
		BIO_free(keybio);
		return false;
	}

	BIO_set_close(keybio, BIO_CLOSE);
	BIO_free(keybio);
	return true;
}

bool  RSACrypto::InitPublicRSA()
{
	BIO* keybio = nullptr;

	keybio = BIO_new_mem_buf((char*)m_strPublicKey.data(), -1);
	if (keybio == NULL)
	{
		printf("Failed to create public key BIO\n");
		return false;
	}
	m_PublickeyRsa = PEM_read_bio_RSA_PUBKEY(keybio, &m_PublickeyRsa, NULL, NULL);
	if (!m_PublickeyRsa)
	{
		printf("Failed to create public RSA\n");
		BIO_set_close(keybio, BIO_CLOSE);
		BIO_free(keybio);
		return false;
	}

	BIO_set_close(keybio, BIO_CLOSE);
	BIO_free(keybio);
	return true;
}

bool RSACrypto::InitRsa()
{
	if (!InitPrivateRSA())
	{
		return false;
	}

	if (!InitPublicRSA())
	{
		return false;
	}

	return true;
}

void RSACrypto::Release()
{
	if (m_PublickeyRsa != nullptr)
	{
		RSA_free(m_PublickeyRsa); m_PublickeyRsa = nullptr;
	}

	if (m_PrivatekeyRsa != nullptr)
	{
		RSA_free(m_PrivatekeyRsa); m_PrivatekeyRsa = nullptr;
	}
}

bool RSACrypto::EncryptByPublicKey(const std::string & src, std::string & encrypted)
{
	std::string result;
	const int keysize = RSA_size(m_PublickeyRsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize - RSA_PKCS1_PADDING_SIZE;
	int inputlen = src.length();

	for (int i = 0; i < inputlen; i += chunksize)
	{
		auto resultsize = RSA_public_encrypt(std::min(chunksize, inputlen - i), (uint8_t*)&src[i], &block[0], (RSA*)m_PublickeyRsa, RSA_PKCS1_PADDING);
		if (resultsize == -1)
		{
			return false;
		}
		encrypted.append((char*)block.data(), resultsize);
	}

	return true;
}

bool RSACrypto::DecryptByPublicKey(const std::string & encrypted, std::string & decrypted)
{
	const int keysize = RSA_size(m_PublickeyRsa);
	std::vector<unsigned char> block(keysize);

	int inputlen = encrypted.length();

	for (int i = 0; i < (int)encrypted.length(); i += keysize)
	{
		int flen = std::min(keysize, inputlen - i);

		auto resultsize = RSA_public_decrypt(flen, (uint8_t*)&encrypted[i], &block[0], m_PublickeyRsa, RSA_PKCS1_PADDING);

		if (resultsize == -1)
		{
			return false;
		}

		decrypted.append((char*)block.data(), resultsize);
	}
	return true;
}

bool RSACrypto::EncryptByPrivateKey(const std::string & src, std::string & encrypted)
{
	std::string result;
	const int keysize = RSA_size(m_PrivatekeyRsa);
	std::vector<unsigned char> block(keysize);
	const int chunksize = keysize - RSA_PKCS1_PADDING_SIZE;
	int inputlen = src.length();

	for (int i = 0; i < (int)src.length(); i += chunksize)
	{
		int flen = std::min<int>(chunksize, inputlen - i);

		std::fill(block.begin(), block.end(), 0);

		auto resultsize = RSA_private_encrypt(flen, (uint8_t*)&src[i], &block[0], m_PrivatekeyRsa, RSA_PKCS1_PADDING);
		if (resultsize == -1)
		{
			return false;
		}

		encrypted.append((char*)block.data(), resultsize);
	}
	return true;
}

bool RSACrypto::DecryptByPrivateKey(const std::string & encrypted, std::string & decrypted)
{
	const int keysize = RSA_size(m_PrivatekeyRsa);
	std::vector<unsigned char> block(keysize);

	for (int i = 0; i < (int)encrypted.length(); i += keysize)
	{
		auto resultsize = RSA_private_decrypt(std::min<int>(keysize, encrypted.length() - i), (uint8_t*)&encrypted[i], &block[0], m_PrivatekeyRsa, RSA_PKCS1_PADDING);
		if (resultsize == -1)
		{
			return false;
		}
		decrypted.append((char*)block.data(), resultsize);
	}

	return true;
}



bool RSACrypto::SignByPrivateKey(const std::string &src, std::string& sign)
{
	EVP_MD_CTX* rsa_sign_ctx = EVP_MD_CTX_create();
	EVP_PKEY* pri_key = EVP_PKEY_new();

	auto clean = [pri_key, rsa_sign_ctx] {
		EVP_PKEY_free(pri_key);
		EVP_MD_CTX_cleanup(rsa_sign_ctx);
	};

	//EVP_PKEY_assign_RSA(pri_key, m_PrivatekeyRsa);
	EVP_PKEY_set1_RSA(pri_key, m_PrivatekeyRsa);
	if (EVP_DigestSignInit(rsa_sign_ctx, NULL, EVP_sha1(), NULL, pri_key) <= 0)
	{
		clean();
		return false;
	}

	if (EVP_DigestSignUpdate(rsa_sign_ctx, src.data(), src.length()) <= 0)
	{
		clean();
		return false;
	}

	size_t sign_len;
	if (EVP_DigestSignFinal(rsa_sign_ctx, NULL, &sign_len) <= 0)
	{
		clean();
		return false;
	}

	sign.resize(sign_len);
	if (EVP_DigestSignFinal(rsa_sign_ctx, (unsigned char*)sign.data(), &sign_len) <= 0)
	{
		clean();
		return false;
	}

	sign.resize(sign_len);
	clean();
	return true;
}

bool RSACrypto::VerifyByPublicKey(const std::string &src, const std::string& sign)
{
	EVP_PKEY* pub_key = EVP_PKEY_new();
	//EVP_PKEY_assign_RSA(pub_key, m_PublickeyRsa);
	EVP_PKEY_set1_RSA(pub_key, m_PublickeyRsa);
	EVP_MD_CTX* rsa_verify_ctx = EVP_MD_CTX_create();

	auto clean = [pub_key, rsa_verify_ctx] {
		EVP_PKEY_free(pub_key);
		EVP_MD_CTX_destroy(rsa_verify_ctx);
	};

	if (EVP_DigestVerifyInit(rsa_verify_ctx, NULL, EVP_sha1(), NULL, pub_key) <= 0)
	{
		clean();
		return false;
	}

	if (EVP_DigestVerifyUpdate(rsa_verify_ctx, src.data(), src.length()) <= 0)
	{
		clean();
		return false;
	}

	if (EVP_DigestVerifyFinal(rsa_verify_ctx, (unsigned char*)sign.data(), sign.length()) <= 0)
	{
		clean();
		return false;
	}

	clean();
	return true;
}