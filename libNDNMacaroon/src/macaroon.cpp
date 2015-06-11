#include <ndn-cxx/name.hpp>
#include <ndn-cxx/encoding/buffer.hpp>
#include "macaroon.hpp"
#include <iostream>
#include <string.h>
#include <assert.h>

namespace macaroons {


  const int MAX_ID_SIZE = 1000;

  char NDNMacaroon::data[MACAROON_MAX_STRLEN];


  std::string macaroon_returncode_strings[] = 
    {"MACAROON_SUCCESS", 
     "MACAROON_OUT_OF_MEMORY",
     "MACAROON_HASH_FAILED",
     "MACAROON_INVALID",
     "MACAROON_TOO_MANY_CAVEATS",
     "MACAROON_CYCLE",
     "MACAROON_BUF_TOO_SMALL",
     "MACAROON_NOT_AUTHORIZED",
     "MACAROON_NO_JSON_SUPPORT"};

  std::string returncodeString (macaroon_returncode returncode)
  {
    // according to macaroon.h from libmacaroon, first enum has value 2048
    return macaroon_returncode_strings[returncode - 2048];
  }
  
  /*
    NDNMacaroon
  */

  NDNMacaroon::NDNMacaroon(std::string serialized)
  {
    enum macaroon_returncode err;
    M = macaroon_deserialize(serialized.c_str(), &err);
    if (M == NULL)
      throw Error("NDNMacaroon::NDNMacaroon: " + returncodeString(err));

  }
  
  NDNMacaroon::NDNMacaroon
  (std::string location,
   uint8_t* key,
   uint8_t* id,
   size_t id_size)
  {
    enum macaroon_returncode err;
    std::cout << err << std::endl;

    M =  macaroon_create((const unsigned char*)location.c_str(), location.size(),
			 (const unsigned char*)key,      MACAROON_SUGGESTED_SECRET_LENGTH,
			 (const unsigned char*)id,       id_size,
			 &err);
    if (M == NULL)
      throw Error("NDNMacaroon::NDNMacaroon: " + returncodeString(err));
  }

    
  NDNMacaroon::~NDNMacaroon() 
  {
    // destroy discharge macaroons
    for (unsigned i=0; i<dischargeMacaroonsSize; i++)
      macaroon_destroy(dischargeMacaroons[i]);
    
    macaroon_destroy(M);
  }

  std::string
  NDNMacaroon::inspect()
  {
    enum macaroon_returncode err;
      
    int result = macaroon_inspect(M, data, MACAROON_MAX_STRLEN, &err);
    if (result < 0)
      throw Error("NDNMacaroon::inspect: " + returncodeString(err));

    return std::string(data);
  }
    
  int 
  NDNMacaroon::verify (NDNMacaroonVerifier* V, 
	  uint8_t* secret,
	  std::string& errorCode)
  {
    enum macaroon_returncode err;

    std::cout << "************ dischargeMacaroonsSize: " << dischargeMacaroonsSize << std::endl;

    int result = macaroon_verify(V->get(), M,
				 secret, MACAROON_SUGGESTED_SECRET_LENGTH,
				 dischargeMacaroons, dischargeMacaroonsSize,
				 &err);
    if (result < 0) 
      errorCode = returncodeString(err);
    // should we throw exception to propagate err to caller? I think
    // it's better to return it as a parameter so if result==-1 the
    // caller can show err
    
    
    return result;
  }
    

  void 
  NDNMacaroon::addFirstPartyCaveat (std::string caveat)
  {
    enum macaroon_returncode err;

    struct macaroon* N = M;

    M = macaroon_add_first_party_caveat
      (M, 
       (const unsigned char*)caveat.c_str(), 
       caveat.size(), 
       &err);

    macaroon_destroy (N);

    if (M == NULL)
      throw Error("NDNMacaroon::addFirstPartyCaveat" + returncodeString(err));

  }
  




  void 
  NDNMacaroon::addThirdPartyCaveat 
  (std::string tp_location, 
   std::string predicate, 
   uint8_t* caveat_key,
   const Encryptor& encryptIdentifier)
  {

    /* 
       caveat_key == RN in the paper
       identifier == Enc(Ka, caveat_key::user=="bob")
    */


    const std::string SEPARATOR = "::";
    const int ID_SIZE = MACAROON_SUGGESTED_SECRET_LENGTH + SEPARATOR.length() + predicate.length();

    unsigned char plain_identifier[MAX_ID_SIZE];


    memcpy((char*)plain_identifier, (char*)caveat_key, MACAROON_SUGGESTED_SECRET_LENGTH);
    memcpy((char*)plain_identifier+MACAROON_SUGGESTED_SECRET_LENGTH, (char*)SEPARATOR.c_str(), SEPARATOR.size()); 
    memcpy((char*)plain_identifier+MACAROON_SUGGESTED_SECRET_LENGTH + SEPARATOR.size(), (char*)predicate.c_str(), predicate.size()); 


    std::cout << "******** identifier_plain: " << std::string(plain_identifier, plain_identifier + ID_SIZE) << std::endl;
    // std::cout << "******** size: " << identifier_plain.size() << std::endl;
    // std::cout << "******** length: " << identifier_plain.length() << std::endl;


    enum macaroon_returncode err;
    struct macaroon* N = M;

    std::cout<< "********************** ID_SIZE: " << ID_SIZE << std::endl;


    ndn::ConstBufferPtr identifier;
    encryptIdentifier(plain_identifier, ID_SIZE, &identifier);

    std::cout << "caveat_key: " << caveat_key << std::endl;
    std::cout << "predicate: " << predicate << std::endl;


    std::cout << "encrypted id: " << std::string(identifier->buf(), identifier->buf() + identifier->size()) << std::endl;
    
    M = macaroon_add_third_party_caveat
      (M,
       reinterpret_cast<const unsigned char*>(tp_location.c_str()), tp_location.size(),       
       reinterpret_cast<const unsigned char*>(caveat_key), MACAROON_SUGGESTED_SECRET_LENGTH,
       reinterpret_cast<const unsigned char*>(identifier->buf()), identifier->size(),
       &err);
    
    macaroon_destroy (N);

  }


  unsigned
  NDNMacaroon::getNumThirdPartyCaveats()
  {
    unsigned n_third_party_caveats = macaroon_num_third_party_caveats(M);
    return n_third_party_caveats;
  }


  // n = 1 ..
  void 
  NDNMacaroon::getThirdPartyCaveat(unsigned n, std::string& third_party_location, ndn::ConstBufferPtr* tp_id_sp)
  {
    // get number of third party caveats in macaroon
    unsigned n_third_party_caveats = macaroon_num_third_party_caveats(M);
    if (n_third_party_caveats < n)
      throw Error ("NDNMacaroon::getThirdPartyCaveat: inexistent third party caveat");

    unsigned char **l3;
    size_t l3_size;
    unsigned char** third_party_id;
    size_t third_party_id_sz;

    int result = macaroon_third_party_caveat(M, n - 1,
					     (const unsigned char**)&l3, &l3_size,
					     (const unsigned char**)&third_party_id, &third_party_id_sz);

    if (result < 0) 
      throw Error ("NDNMacaroon::getThirdPartyCaveat");

    third_party_location = std::string(reinterpret_cast<char*>(l3), l3_size);
    *tp_id_sp = std::make_shared<ndn::Buffer>(third_party_id, third_party_id_sz);
  }




  std::string
  NDNMacaroon::getDischargeMacaroon (unsigned i)
  {
    enum macaroon_returncode err;
    int result = macaroon_serialize(dischargeMacaroons[i-1], data, MACAROON_MAX_STRLEN, &err);
 
    if (result < 0) 
      throw Error("NDNMacaroon::getDischargeMacaroon" + returncodeString(err));

    return data;
  }



  // Serialize macaroon
  std::string
  NDNMacaroon::serialize()
  {
    enum macaroon_returncode err;
    int result = macaroon_serialize(M, data, MACAROON_MAX_STRLEN, &err);

    if (result < 0)
      throw Error("NDNMacaroon::serialize" + returncodeString(err));


    return data;
  } 



  unsigned
  NDNMacaroon::getNumDischargeM(){
    return dischargeMacaroonsSize;
  }


  void
  NDNMacaroon::addDischarge(std::string d)
  {
    enum macaroon_returncode err;

    struct macaroon* D = macaroon_deserialize(d.c_str(), &err);

    if (D == NULL)
      throw Error("NDNMacaroon::addDischarge: " + returncodeString(err));

    dischargeMacaroons[dischargeMacaroonsSize++] = D;
  }

  
  void
  NDNMacaroon::addDischargeAndPrepare(std::string d)
  {
    enum macaroon_returncode err;

    struct macaroon* D = macaroon_deserialize(d.c_str(), &err);

    if (D == NULL)
      throw Error("NDNMacaroon::addDischargeAndPrepare: " + returncodeString(err));


    struct macaroon* DM = macaroon_prepare_for_request(M,D,&err);
    if (D == NULL)
      throw Error("NDNMacaroon::addDischargeAndPrepare: " + returncodeString(err));


    // Add discharge macaroon to array
    dischargeMacaroons[dischargeMacaroonsSize++] = DM;

    macaroon_destroy(D);
    // macaroon_serialize(DM, data, MACAROON_MAX_STRLEN, &err);
    // macaroon_destroy(DM);
  }


  std::string
  NDNMacaroon::getLocation()
  {
    const unsigned char* location;
    size_t location_sz;

    macaroon_location(M,
		      &location, &location_sz);

    return std::string(location, location + location_sz);
    
  }

  std::string
  NDNMacaroon::getIdentifier()
  {
    const unsigned char* identifier;
    size_t identifier_sz;

    macaroon_identifier(M,
		      &identifier, &identifier_sz);

    return std::string(identifier, identifier + identifier_sz);
  }



  /*
    NDNMacaroonVerifier
  */

  NDNMacaroonVerifier::NDNMacaroonVerifier()
  {
    V = macaroon_verifier_create();
    if (V == NULL)
      throw Error("NDNMacaroonVerifier::NDNMacaronVerifier");

  }

  NDNMacaroonVerifier::~NDNMacaroonVerifier()
  {
    macaroon_verifier_destroy(V);
  }


  void
  NDNMacaroonVerifier::satisfyExact(std::string caveat) 
  {
    enum macaroon_returncode err;
    int result =  
      macaroon_verifier_satisfy_exact
      (V, (const unsigned char*)caveat.c_str(), caveat.size(), &err);

    if (result < 0) 
      throw Error("NDNMacaroonVerifier::satisfyExact: " + returncodeString(err));
  }

  void
  NDNMacaroonVerifier::satisfyGeneral
  (int (*general_check)(void* f, const unsigned char* pred, size_t pred_sz),
   void* f)
  {
    enum macaroon_returncode err;
    int result = macaroon_verifier_satisfy_general(V, general_check, f, &err);
    if (result < 0) 
      throw Error("NDNMacaroonVerifier::satisfyGeneral: " + returncodeString(err));
  }

  macaroon_verifier *
  NDNMacaroonVerifier::get()
  {
    return V;
  }

}// namespace macaroons


