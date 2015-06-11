#include <sec-tpm-file-enc.hpp>

#include <ndn-cxx/security/cryptopp.hpp>
#include <macaroon.hpp>


namespace macaroons{

  std::string encode (std::string bits) 
  {
    std::string encoded;
    encoded.clear();
    CryptoPP::StringSource
      (reinterpret_cast<const uint8_t*>(bits.c_str()), bits.size(), true,
       new CryptoPP::HexEncoder
       (
	new CryptoPP::StringSink(encoded)
	) // HexEncoder
       ); // StringSource
    return encoded;
  }
  
  
  std::string decode (std::string bits) 
  {
    std::string decoded;
    decoded.clear();
    CryptoPP::StringSource
      (reinterpret_cast<const uint8_t*>(bits.c_str()), bits.size(), true,
       new CryptoPP::HexDecoder
       (
	new CryptoPP::StringSink(decoded)
	) // HexDecoder
       ); // StringSource
    return decoded;
  }




  /* 
     Returns in identifierP the encrypted plainIdentifier using either
     symmetric or public key, depending on the value of the 4th
     argument
  */
  void encryptIdentifier (unsigned char* plainIdentifier, 
			  size_t plainIdentifier_size,
			  ndn::ConstBufferPtr* identifierP,
			  bool symmetric, 
			  std::string tp_key, 
			  ndn::SecTpmFileEnc* m_secTpmFile)
  {
    std::cout << "************************** " << plainIdentifier_size << std::endl;


    // If symmetric encryption is required, and tp_key does not exist,
    // create it
    if (symmetric) 
      if (!m_secTpmFile->doesKeyExistInTpm(tp_key, ndn::KEY_CLASS_SYMMETRIC)){
        ndn::AesKeyParams aesKeyParams;
        m_secTpmFile->generateSymmetricKeyInTpm(tp_key, aesKeyParams);
      }
      
    // depending on symmetric parameter, now we encrypt either with public or symmetric key
    ndn::Name key_name(tp_key);

    *identifierP =  
      m_secTpmFile->encryptInTpm(reinterpret_cast<const uint8_t*>(plainIdentifier), 
				 plainIdentifier_size,
				 // identifier_plain.size(), 
				 key_name, 
				 symmetric);
  }




  /*
    Function to check generic predicate
    check_time function retrieved from hyperdex-1.6.0: daemon/auth.cc
  */
#define TIME_PRED "time < "
#define TIME_PRED_SZ (sizeof(TIME_PRED) - 1)

  int
  check_time(void* t, const unsigned char* pred, size_t pred_sz)
  {
    if (pred_sz < TIME_PRED_SZ ||
        memcmp(pred, TIME_PRED, TIME_PRED_SZ) != 0)
      {
        return -1;
      }
  
    std::string tmp(reinterpret_cast<const char*>(pred) + TIME_PRED_SZ, pred_sz - TIME_PRED_SZ);
    std::cout << ">>> expiry " << tmp << std::endl;
  
    ndn::time::system_clock::TimePoint expiry_tp = ndn::time::fromString(tmp);
    uint64_t expiry = (ndn::time::toUnixTimestamp(expiry_tp)).count();
  
    std::cout << ">>> t " << *reinterpret_cast<uint64_t*>(t) << std::endl;
  
    return (*reinterpret_cast<uint64_t*>(t) < expiry) ? 0 : -1;
  }
  



  const unsigned MAX_SESSION_KEY_SIZE = 128;
  uint8_t session_key_bits [MAX_SESSION_KEY_SIZE];  
  
  ndn::ConstBufferPtr 
  generateSessionKey(ndn::Name& public_key_name, ndn::Name& session_key_name, size_t key_size)
  {
          // Generate session key
          ndn::SecTpmFileEnc m_secTpmFile;


          m_secTpmFile.generateRandomBlock(session_key_bits, key_size);


          // add session_key_bits to /session-key name
          ndn::SecTpmFileEnc secTpmFile;
          secTpmFile.setSymmetricKeyToTpm(session_key_name, session_key_bits, key_size);	

    
          // Encrypt session key with public key of third party
          // enc-session-key = ENCrsa(Ktp, session-key)
          ndn::ConstBufferPtr enc_session_key;
          enc_session_key =  
            m_secTpmFile.encryptInTpm(session_key_bits, 
				      key_size,
				      public_key_name, 
				      false  /* public_key */);

	  return enc_session_key;
  }

}// namespace macaroons
