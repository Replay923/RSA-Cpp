#pragma once

#include <string>


class RSACrypto
{
public:
	RSACrypto(
		const std::string& public_key,
		const std::string& private_key) :
		m_strPublicKey(public_key),
		m_strPrivateKey(private_key),
		m_PublickeyRsa(nullptr), m_PrivatekeyRsa(nullptr)
	{

	}

	virtual ~RSACrypto();

	bool InitRsa();

	void Release();


	bool EncryptByPublicKey(const std::string& src, std::string& encrypted);
	bool DecryptByPublicKey(const std::string& encrypted, std::string& decrypted);


	bool EncryptByPrivateKey(const std::string& src, std::string& encrypted);
	bool DecryptByPrivateKey(const std::string& encrypted, std::string& decrypted);


	bool SignByPrivateKey(const std::string &src, std::string& sign);
	bool VerifyByPublicKey(const std::string &src, const std::string& sign);

private:
	bool InitPrivateRSA();
	bool InitPublicRSA();
private:

	const std::string & m_strPublicKey;
	const std::string & m_strPrivateKey;

	RSA *m_PublickeyRsa;
	RSA *m_PrivatekeyRsa;
};

