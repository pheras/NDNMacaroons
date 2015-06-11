#include <ndn-cxx/encoding/buffer.hpp>

#include <boost/function.hpp>
#include <boost/bind.hpp>

#include <boost/shared_ptr.hpp>

#include <macaroons.h>
#include <string>


namespace macaroons {

  class NDNMacaroonVerifier;

  class NDNMacaroon {
  public:
    class Error : public std::runtime_error
    {
    public:
      explicit
      Error(const std::string& what)
	: std::runtime_error(what)
      {
      }
    };
    

    NDNMacaroon(std::string serialized);
    
    NDNMacaroon
    (std::string location,
     uint8_t* key,
     uint8_t* id,
     size_t id_size);
    
    ~NDNMacaroon();
    
    std::string
    inspect();

    
    int 
    verify (NDNMacaroonVerifier* V, 
	    uint8_t* secret,
	    std::string& errorCode);

    
    //    typedef boost::function<std::string(const std::string)> Encryptor;
    typedef boost::function<void(unsigned char*, size_t, ndn::ConstBufferPtr*)> Encryptor;
    
    // Last argument is a callback used to generate the cId == Enc
    // (caveat_key::predicate) It depends on the protocol between the
    // principal adding the third party caveat and the third
    // party. Encrypting with symmetric shared key or with the public
    // key of third party are two possibilities. 
    void 
    addThirdPartyCaveat 
    (std::string tp_location, 
     std::string predicate, 
     uint8_t* caveat_key,
     const Encryptor& encryptIdentifier);


      
    void 
    addFirstPartyCaveat (std::string caveat);
    

      
    // get number of third party caveats in macaroon
    unsigned
    getNumThirdPartyCaveats();
    
    // returns the nth third-party location and id. n = 1..
    void 
    getThirdPartyCaveat(unsigned n, std::string& third_party_location, ndn::ConstBufferPtr* tp_id_sp);

    
    std::string
    getDischargeMacaroon (unsigned i);
    
    // Serialize macaroon
    std::string
    serialize();

    unsigned
    getNumDischargeM();

    void
    addDischarge(std::string d);

    // prepare and store discharge macaroon
    void
    addDischargeAndPrepare(std::string d);

    std::string
    getLocation();

    std::string
    getIdentifier();
      
  private:
    struct macaroon *M;

    // Discharge macaroons. Is 20 enough? Dunno what's the right number
    struct macaroon* dischargeMacaroons[20];

    // number of discharge macaroons already obtained
    size_t dischargeMacaroonsSize = 0;

    // Beware, multiple threads can't share this static
    static char data[MACAROON_MAX_STRLEN];

  };

  
  /*
    NDNMacaroonVerifier
  */
  
  class NDNMacaroonVerifier
  {
  public:
    class Error : public std::runtime_error
    {
    public:
      explicit
      Error(const std::string& what)
	: std::runtime_error(what)
      {
      }
    };

    NDNMacaroonVerifier();

    ~NDNMacaroonVerifier();

    void
    satisfyExact(std::string caveat);
    

    void
    satisfyGeneral
    (int (*general_check)(void* f, const unsigned char* pred, size_t pred_sz),
     void* f);
  
    macaroon_verifier *get();

  private:
    struct macaroon_verifier *V;
  };

}// namespace macaroons


