#include "Release/cryptopp840/cryptlib.h"
#include "Release/cryptopp840/secblock.h"
#include "Release/cryptopp840/osrng.h" 
#include "Release/cryptopp840/files.h"
#include "Release/cryptopp840/hex.h"
#include "Release/cryptopp840/modes.h"


using namespace CryptoPP;



void KeyGen(SecByteBlock& key)
{
	AutoSeededRandomPool prng;
	prng.GenerateBlock(key, key.size());
}



void Sign(SecByteBlock& key, std::string& plainText, std::string& mac, std::string& hmacText) 
{
	HMAC<SHA256> hmac(key, key.size());

	StringSource ss2(plainText, true,
		new HashFilter(hmac,
			new StringSink(mac)));

	StringSource ss3(mac, true,
		new HexEncoder(
			new StringSink(hmacText)));
}



bool Verify(SecByteBlock& key, std::string& plainText, std::string& mac)
{
	try
	{
		HMAC<SHA256> hmac(key, key.size());
		const int flags = HashVerificationFilter::THROW_EXCEPTION | HashVerificationFilter::HASH_AT_END;

		StringSource(plainText + mac, true,
			new HashVerificationFilter(hmac, NULL, flags)
		);

		return true;
	}
	catch (const CryptoPP::Exception& e)
	{
		return false;
	}
}



int main()
{
	SecByteBlock key(32);
	KeyGen(key);

	std::string plainText = "HMAC text";
	std::string mac;
	std::string hmacText;

	Sign(key, plainText, mac, hmacText);
	std::cout << "plain text: " << plainText << std::endl;
	std::cout << "hmac: " << hmacText << std::endl;
	mac[0] = 's';

	if (Verify(key, plainText, mac)) 
	{
		std::cout << "Verified message" << std::endl;
	}
	else
	{
		std::cout << "Unverified message" << std::endl;
	}

	return 0;
}