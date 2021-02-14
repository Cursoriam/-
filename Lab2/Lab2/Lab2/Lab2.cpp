#include "Debug/cryptopp840/cryptlib.h"
#include "Debug/cryptopp840/secblock.h"
#include "Debug/cryptopp840/osrng.h" 
#include "Debug/cryptopp840/files.h"
#include "Debug/cryptopp840/hex.h"
#include "Debug/cryptopp840/modes.h"


using namespace CryptoPP;



void KeyGen(SecByteBlock& key, SecByteBlock& iv)
{
	AutoSeededRandomPool prng;
	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());
}



void Enc(SecByteBlock& key, SecByteBlock& iv, std::string& plaintext, std::string& ciphertext)
{
	// Encryption object
	CTR_Mode<AES>::Encryption enc;
	enc.SetKeyWithIV(key, key.size(), iv, iv.size());

	// Perform the encryption
	ciphertext.resize(plaintext.size());
	enc.ProcessData((byte*)&ciphertext[0], (const byte*)plaintext.data(), plaintext.size());
}



void Dec(SecByteBlock& key, SecByteBlock& iv, std::string& ciphertext, std::string& decrypted)
{
	// Decryption object
	CTR_Mode<AES>::Decryption dec;
	dec.SetKeyWithIV(key, key.size(), iv, iv.size());

	// Perform the decryption
	decrypted.resize(ciphertext.size());
	dec.ProcessData((byte*)&decrypted[0], (const byte*)ciphertext.data(), ciphertext.size());
}



int main()
{
	std::string plaintext = "CTR Mode Test", ciphertext, decrypted;

	SecByteBlock key(32), iv(16);
	KeyGen(key, iv);

	std::cout << "Plaintext: " << plaintext << std::endl;

	Enc(key, iv, plaintext, ciphertext);

	std::cout << "Ciphertext: " << ciphertext << std::endl;

	Dec(key, iv, ciphertext, decrypted);

	std::cout << "Decrypted: " << decrypted << std::endl;

	return 0;
}