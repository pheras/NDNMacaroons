#include "sec-tpm-file-enc.hpp"

namespace macaroons{

  std::string encode (std::string bits);
  std::string decode (std::string bits);


  void encryptIdentifier (unsigned char* plainIdentifier, 
			  size_t plainIdentifier_size,
			  ndn::ConstBufferPtr* identifierP,
			  bool symmetric, 
			  std::string tp_key, 
			  ndn::SecTpmFileEnc* m_secTpmFile);

  int
  check_time(void* t, const unsigned char* pred, size_t pred_sz);


  // Generates a new session key of key_size bits, stores it with
  // session_key_name, and returns it encrypted by public_key_name
  ndn::ConstBufferPtr 
  generateSessionKey(ndn::Name& public_key_name, ndn::Name& session_key_name, size_t key_size);
    

}
