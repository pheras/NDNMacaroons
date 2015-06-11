#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/util/time.hpp>

#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>

#include <boost/regex.hpp>

#include <map>


/************** Macaroon related declarations ****************/
namespace macaroons{



  std::string first_party_caveat_1 = "account = 3735928559";
  std::string first_party_caveat_2 = "time < 2016-02-27 08:22:00";
  std::string first_party_caveat_3 = "email = alice@example.org";
  std::string first_party_caveat_4 = "IP = 127.0.0.1";
  std::string first_party_caveat_5 = "browser = Chrome";
  std::string first_party_caveat_6 = "action = deposit";
  std::string first_party_caveat_7 = "action = withdraw";
  std::string first_party_caveat_8 = "OS = Windows XP";


  // Map <id, secret>
  std::map<std::string, std::string> idsToSecrets;


  //
  // create_macaroon
  //
  std::shared_ptr<macaroons::NDNMacaroon> 
  create_macaroon(const std::string location, ndn::SecTpmFileEnc* m_secTpmFile)
  {
    // 
    // 1. Create id, secret, and store id->secret in idsToSecrets
    //

    // Create identifier as random number
    uint8_t id[MACAROON_SUGGESTED_SECRET_LENGTH];
    m_secTpmFile->generateRandomBlock(id, MACAROON_SUGGESTED_SECRET_LENGTH);
    // Create secret as random number
    uint8_t secret[MACAROON_SUGGESTED_SECRET_LENGTH];
    m_secTpmFile->generateRandomBlock(secret, MACAROON_SUGGESTED_SECRET_LENGTH);

    macaroons::idsToSecrets[std::string(id, id + MACAROON_SUGGESTED_SECRET_LENGTH)] =
      std::string(secret, secret + MACAROON_SUGGESTED_SECRET_LENGTH);

    //
    // 2. create macaroon
    //
    std::shared_ptr<macaroons::NDNMacaroon> M = 
         std::make_shared<macaroons::NDNMacaroon>(location, secret, id,
                                                  MACAROON_SUGGESTED_SECRET_LENGTH);

    //
    // 3. add first party caveats
    //
    M->addFirstPartyCaveat (first_party_caveat_1);
    M->addFirstPartyCaveat (first_party_caveat_2);
    M->addFirstPartyCaveat (first_party_caveat_6);
    
    return M;

  }// create_macaroon


  //
  // compose_verifier
  //
  void
  compose_verifier (NDNMacaroonVerifier* V, std::string operationType)
  {
    V->satisfyExact(first_party_caveat_1);
    V->satisfyExact(first_party_caveat_3);
    V->satisfyExact(first_party_caveat_4);
    V->satisfyExact(first_party_caveat_5);
                     
    if (operationType == "deposit")  {
      V->satisfyExact(first_party_caveat_6);
    } 
    else if (operationType == "withdraw") {
      V->satisfyExact(first_party_caveat_7);
    }
      
    // add check for time now
    // ndn::time::system_clock::TimePoint now = ndn::time::system_clock::now();
    // uint64_t time = (ndn::time::toUnixTimestamp(now)).count();
    // std::cout << ">>> after now " << time << std::endl;
    // V->satisfyGeneral(macaroons::check_time,
    //                   &time);
  }// compose_verifier


  //
  // verify
  //
  int
  verify(NDNMacaroon *M, std::string operationType)
  {
    //
    // 1. create verifier
    //
    NDNMacaroonVerifier verifier;

    //
    // 2. add "exact" rules (x = b)
    //
    macaroons::compose_verifier(&verifier, operationType);

    //
    // 3. add general rules (ex. time < ...)
    //

    // IMPORTANT: Note that satisfyGeneral gets a reference to time,
    // and stores it in the verifier. This reference is used later,
    // when NDNMacaroon::verify, so time must be declared in the same
    // scope than the call to verify, or shared pointers must be used.

    ndn::time::system_clock::TimePoint now = ndn::time::system_clock::now();
    uint64_t time = (uint64_t)ndn::time::toUnixTimestamp(now).count();
    verifier.satisfyGeneral(macaroons::check_time, (void*)(&time));

    //
    // 4. verify the macaroon M with the verifier V
    //
    std::string errorCode;
    int result = M->verify(&verifier, 
                           (uint8_t *)macaroons::idsToSecrets[M->getIdentifier()].c_str(), 
                           errorCode);

    std::cout << "Verifying ..." << std::endl;
    if (!result) {
       std::cout << "verified!\n";
    }
    else {
       std::cout << "not verified! errorCode: " + errorCode << std::endl;
    }

    // 
    // 5. Delete mapping id -> secret. A macaroon is serviced only for
    // one request in this application
    //
    std::cout << "Verifying ..." << std::endl;
    //macaroons::idsToSecrets.erase (M->getIdentifier());
    std::cout << "Size of idsToSecrets: " << macaroons::idsToSecrets.size() << std::endl;

    return result;
  } //verify
    
}// namespace macaroons






std::string FILENAME="./config/validation-producer.conf";

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
  // Additional nested namespace could be used to prevent/limit name contentions
  namespace examples {

    class Producer : noncopyable
    {
    public:

      Producer()
        : m_validator(m_face)
      {

        try {
          std::cout << "OPEN File= " << FILENAME << std::endl;
          m_validator.load(FILENAME);
        }
        catch (const std::exception &e ) {
          std::cout << "Can not load File= " << FILENAME << ". Error: " << e.what()
            <<  std::endl;
          exit(1);
        }

      }

      ~Producer()
      {
      }

      enum {
        // 0  --> /example
        // 1  --> /producer
        COMMAND_POS         = 2, // Position of command in name.
        SESSION_KEY_POS     = 3, // Position session Key
        MACAROON_POS        = 4, // Position of macaroon in name. 
                                 // Discharge i is in MACAROON_POS + i ...
        INTEREST_SIG_VALUE  = -1,
        INTEREST_SIG_INFO   = -2
      };

      const std::string LOCATION = "/example/producer";

      void
      run()
      {
        m_face.setInterestFilter(LOCATION,
                                 bind(&Producer::onInterest, this, _1, _2),
                                 RegisterPrefixSuccessCallback(),
                                 bind(&Producer::onRegisterFailed, this, _1, _2));

	m_face.setInterestFilter("/ndn/keys/bob",
	 			 bind(&Producer::onKeyInterest, this, _1, _2),
	 			 RegisterPrefixSuccessCallback(),
	 			 bind(&Producer::onRegisterFailed, this, _1, _2));
	
        m_face.processEvents();
      }

    private:
      void
      onKeyInterest(const InterestFilter& filter, const Interest& interest)
      {
	Name keyName = ndn::Name("/ndn/keys/bob/" + interest.getName().at(4).toUri());

	std::cout << keyName << std::endl;

	std::cout << "<< I Certificate: " << interest << std::endl;


	try {
	  // Create Data packet
	  shared_ptr<IdentityCertificate> cert = 
	    m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(keyName));
	    //	    m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/bob/ksk-1428573187822"));


	  // Return Data packet to the requester
	  //std::cout << ">> CERTIFICATE: " << *cert << std::endl;
	  m_face.put(*cert);
	}
	catch (const std::exception& ) {
	  std::cout << "The certificate: " << interest.getName() 
		    << " does not exist"  << std::endl;
	}
      }

      void
      onInterest(const InterestFilter& filter, const Interest& interest)
      {
        ndn::SecTpmFileEnc m_secTpmFile;
        
        std::string content;
        Name interestName = interest.getName();

        std::string command = interestName.at(COMMAND_POS).toUri();

        if (command == "getMacaroon") {

          std::cout << "Request Macaroon: validating interest..." << std::endl;

          ndn::Signature signature(interestName[INTEREST_SIG_INFO].blockFromValue(),
                                   interestName[INTEREST_SIG_VALUE].blockFromValue());

          SignatureSha256WithRsa sig(signature);
          const KeyLocator &keyLocator = sig.getKeyLocator();

          std::string keyLocatorStr = keyLocator.getName().toUri();

          std::cout << "KEY_LOCATOR= " << keyLocatorStr << std::endl;

          boost::regex id1("(.*)/KEY/ksk-(.*)/ID-CERT");
          boost::regex id2("(.*)/KEY/(.*)/ksk-(.*)/ID-CERT");
          boost::cmatch matches;
          std::string identity;

          if (boost::regex_match(keyLocatorStr.c_str(), matches, id1)) {
                 identity = matches[1];
          } else if (boost::regex_match(keyLocatorStr.c_str(), matches, id2)) {
                 //hierarchical certificates
                 identity = matches[1]+ "/" + matches[2];
          } else {
                 std::cout << "NoMatches. Unknow KeyLocator format" << std::endl;
          }

          std::cout << "IDENTITY=" << identity << std::endl;

          m_validator.validate(interest,
                         bind(&Producer::onValidated, this, _1),
                         bind(&Producer::onValidationFailed, this, _1, _2));

        } else if (command == "deposit" or command == "withdraw") {
          //
          // extract macaroon from name 
          //
          std::cout << "Request Operation: " << command << std::endl;


          // GET SESSION KEY + MACAROON & DISCHARGE MACAROON

          ndn::Name session_key_name("/session-key-producer-consumer2");
          getSessionKeyFromInterest(make_shared<Interest>(interest), 
                                    SESSION_KEY_POS, session_key_name);

          //
          // extract macaroon from name 
          //
          ndn::name::Component encrypted_macaroon = interest.getName().at(MACAROON_POS);

          // Decrypt macaroon
          ndn::ConstBufferPtr decrypted_macaroon =
            m_secTpmFile.decryptInTpm(encrypted_macaroon.value(),
                                    encrypted_macaroon.value_size(),
                                    session_key_name,
                                    /*symmetric*/ true);

          std::cout << "==========> decrypted macaroon: " 
                    << std::string(decrypted_macaroon->buf(), 
                                   decrypted_macaroon->buf() + decrypted_macaroon->size()) 
                    << std::endl;

          std::cout << "Construyendo macaroon" << std::endl;

          // Create Macaroon
          macaroons::NDNMacaroon M(std::string(decrypted_macaroon->buf(), 
                     decrypted_macaroon->buf() + decrypted_macaroon->size()));
          std::cout << "Macaroon construido" << std::endl;

          //
          // extract discharge macaroons from name
          //
          std::cout << "*** num third party requests " << M.getNumThirdPartyCaveats() << std::endl;
          for (unsigned i=1; i <= M.getNumThirdPartyCaveats(); i++) {
            //std::string dm = interest.getName().at(MACAROON_POS + i).toUri();
            //M.addDischarge(dm);
            //std::cout << "*** added discharge, nms: " << M.getNumDischargeM() << std::endl;
            ndn::name::Component encrypted_dm = interest.getName().at(MACAROON_POS+i);
            // Decrypt dm
            ndn::ConstBufferPtr decrypted_dm =
              m_secTpmFile.decryptInTpm(encrypted_dm.value(),
                                        encrypted_dm.value_size(),
                                        session_key_name,
                                        /*symmetric*/ true);
            // Bind DischargeMacaroon 
            M.addDischarge(std::string(decrypted_dm->buf(), 
                           decrypted_dm->buf() + decrypted_dm->size()));
            std::cout << "*** added discharge, nms: " << M.getNumDischargeM() << std::endl;
         
          }

          // Verify macaroon 
          int result = macaroons::verify (&M, command);
          if (!result) {
            content = std::string("verified!");
          }
          else {
            content = std::string("not verified!");
          }

          //
          // Prepare and send reply containing the result of 
          // the operation if [withdraw|deposit] was called
          //

          // Create new name, based on Interest's name
          Name dataName(interest.getName());
          dataName
            .append("result") // add "result" component to Interest name
            .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

          shared_ptr<Data> data = make_shared<Data>();
          data->setName(dataName);
          data->setFreshnessPeriod(time::seconds(0));
          data->setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.size());

	  // m_keyChain.setDefaultKeyNameForIdentity("/ndn/keys/bob/ksk-1428573187822");
	  // m_keyChain.signByIdentity(*data, Name("/ndn/keys/bob"));
	  m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/bob/ksk-1428573187822"));

          std::cout << ">> D: " << *data << std::endl;
          m_face.put(*data);
        } else {
           std::cout << "Interest ERROR " << std::endl;
        }
      } //onInterest


      void
      onRegisterFailed(const Name& prefix, const std::string& reason)
      {
        std::cerr << "ERROR: Failed to register prefix \""
                  << prefix << "\" in local hub's daemon (" << reason << ")"
                  << std::endl;
        m_face.shutdown();
      }

      void
      getSessionKeyFromInterest(const shared_ptr <const Interest> & interest, 
                    const unsigned sessionKeyPos,
                    const Name session_key_name)
      {
        ndn::SecTpmFileEnc m_secTpmFile;

        // Get session_key from interestName
        ndn::name::Component encrypted_session_key = interest->getName().at(sessionKeyPos);

        // Decrypt session_key sent by consummer, using bob private key
        ndn::Name pub_key_name("/ndn/keys/bob/dsk-1428573298310");
        ndn::ConstBufferPtr session_key_bits =
          m_secTpmFile.decryptInTpm(encrypted_session_key.value(),
                                    encrypted_session_key.value_size(),
                                    pub_key_name,
                                    /*no symmetric*/ false);

        // save session_key_bits with /session-key name inside m_secTpmFile
        m_secTpmFile.setSymmetricKeyToTpm(session_key_name, 
                                        session_key_bits->buf(), 
                                        session_key_bits->size());

        std::cout << "Session key name=" << session_key_name << " added to secTpmFile" << std::endl;
      }
      
      void
      onValidated(const shared_ptr<const Interest>& interest)
      {
        ndn::SecTpmFileEnc m_secTpmFile;

        std::cout << "Validated INTEREST -> Generating macaroon" << std::endl;

        ndn::Name session_key_name("/session-key-producer-consumer1");
        getSessionKeyFromInterest(interest, SESSION_KEY_POS, session_key_name);

 
        // Create macaroon
        std::shared_ptr<macaroons::NDNMacaroon> M = macaroons::create_macaroon(LOCATION, 
                                                                               &m_secTpmFile);
        std::cout << ">>>" << std::endl;

        // Encrypt serialized macaroon with session_key
        std::string serialized_macaroon = M->serialize();
        ndn::ConstBufferPtr encrypted_serialized_macaroon =
          m_secTpmFile.encryptInTpm((uint8_t*) serialized_macaroon.c_str(),
                                  serialized_macaroon.size(),
                                  session_key_name,
                                  true  /* symmetric */);
        std::cout << ">>>" << std::endl;


        // Build Data packet: interestName/result/version content: enc(serialized_macaroon)
        Name dataName(interest->getName());
        dataName
            .append("result") // add "result" component to Interest name
            .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

        shared_ptr<Data> data = make_shared<Data>();
        data->setName(dataName);
        data->setFreshnessPeriod(time::seconds(0));
        data->setContent(encrypted_serialized_macaroon);

        // Sign data packet
	m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/bob/ksk-1428573187822"));
	
        std::cout << ">> D: " << *data << std::endl;
        m_face.put(*data);
      }

      void
      onValidationFailed(const shared_ptr<const Interest>& interest, const std::string& failureInfo)
      {
        std::cerr << "Not validated INTEREST " << interest->getName()
                  << ". The failure info: " << failureInfo << std::endl;
      }



    private:
      Face m_face;
      KeyChain m_keyChain;
      ValidatorConfig m_validator;




    };

  } // namespace examples
} // namespace ndn



int
main(int argc, char** argv)
{


  ndn::examples::Producer producer;
  try {
    producer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}


