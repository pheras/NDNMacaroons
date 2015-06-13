#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <ndn-cxx/util/time.hpp>

#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>

#include <boost/regex.hpp>

#include <map>


const std::string KEYNAMES_FILENAME="./keys.txt";
const std::string VALIDATOR_FILENAME="./config/validation-producer.conf";

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
// Additional nested namespace could be used to prevent/limit name contentions
namespace ndn {

namespace examples {

    class Producer : noncopyable
    {
    public:

      Producer()
        : m_validator(m_face)
      {
        loadKeyNames();

        try {
          std::cout << "OPEN File= " << VALIDATOR_FILENAME << std::endl;
          m_validator.load(VALIDATOR_FILENAME);
        }
        catch (const std::exception &e ) {
          std::cout << "Can not load File= " << VALIDATOR_FILENAME << ". Error: " << e.what()
            <<  std::endl;
          exit(1);
        }

      }

      ~Producer()
      {
      }

      void
      run()
      {

        // Waits interest PRODUCER_PREFIX=/example/producer
        m_face.setInterestFilter(PRODUCER_PREFIX,
                                 bind(&Producer::onInterest, this, _1, _2),
                                 RegisterPrefixSuccessCallback(),
                                 bind(&Producer::onRegisterFailed, this, _1, _2));

        // Waits interest producer identity, to provide producer key
	m_face.setInterestFilter(m_producerIdentity,
	 			 bind(&Producer::onKeyInterest, this, _1, _2),
	 			 RegisterPrefixSuccessCallback(),
	 			 bind(&Producer::onRegisterFailed, this, _1, _2));
	
        m_face.processEvents();
      }

    private:

      void
      loadKeyNames()
      {
         std::ifstream is(KEYNAMES_FILENAME.c_str());
         std::string line;
         if (is.is_open()) {
            std::getline(is, line);
            m_princKeyNames[PRODUCER_KSK] = line;
            std::cout <<  " PRODUCER_KSK = " << m_princKeyNames[PRODUCER_KSK] << std::endl;

            std::getline(is, line);
            m_princKeyNames[PRODUCER_DSK] = line;
            std::cout <<  " PRODUCER_DSK = " << m_princKeyNames[PRODUCER_DSK] << std::endl;

            is.close();

            boost::regex identity("(.*)/dsk-(.*)");
            boost::cmatch matches;

            if (boost::regex_match(line.c_str(), matches, identity)) {
                 m_producerIdentity = matches[1];
            }
            std::cout << "producer identity = " << m_producerIdentity << std::endl;
         }
      }


      std::shared_ptr<macaroons::NDNMacaroon> 
      create_macaroon(const std::string location, ndn::SecTpmFileEnc* m_secTpmFile)
      {
        // 1. Create id, secret, and store id->secret in idsToSecrets

        // Create identifier as random number
        uint8_t id[MACAROON_SUGGESTED_SECRET_LENGTH];
        m_secTpmFile->generateRandomBlock(id, MACAROON_SUGGESTED_SECRET_LENGTH);
        // Create secret as random number
        uint8_t secret[MACAROON_SUGGESTED_SECRET_LENGTH];
        m_secTpmFile->generateRandomBlock(secret, MACAROON_SUGGESTED_SECRET_LENGTH);

        idsToSecrets[std::string(id, id + MACAROON_SUGGESTED_SECRET_LENGTH)] =
          std::string(secret, secret + MACAROON_SUGGESTED_SECRET_LENGTH);

        // 2. create macaroon
        std::shared_ptr<macaroons::NDNMacaroon> M = 
            std::make_shared<macaroons::NDNMacaroon>(location, secret, id,
                                                     MACAROON_SUGGESTED_SECRET_LENGTH);

        // 3. add first party caveats
        M->addFirstPartyCaveat (first_party_caveat_1);
        M->addFirstPartyCaveat (first_party_caveat_2);
        M->addFirstPartyCaveat (first_party_caveat_6);
    
        return M;

      }// create_macaroon

      void
      compose_verifier (macaroons::NDNMacaroonVerifier* V, std::string operationType)
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
        // V->satisfyGeneral(macaroons::check_time, &time);
      }// compose_verifier


      int
      verify(macaroons::NDNMacaroon *M, std::string operationType)
      {
        // 1. create verifier
        macaroons::NDNMacaroonVerifier verifier;

        // 2. add "exact" rules (x = b)
        compose_verifier(&verifier, operationType);

        // 3. add general rules (ex. time < ...)

        // IMPORTANT: Note that satisfyGeneral gets a reference to time,
        // and stores it in the verifier. This reference is used later,
        // when NDNMacaroon::verify, so time must be declared in the same
        // scope than the call to verify, or shared pointers must be used.

        ndn::time::system_clock::TimePoint now = ndn::time::system_clock::now();
        uint64_t time = (uint64_t)ndn::time::toUnixTimestamp(now).count();
        verifier.satisfyGeneral(macaroons::check_time, (void*)(&time));

        // 4. verify the macaroon M with the verifier V
        std::string errorCode;
        int result = M->verify(&verifier, 
                               (uint8_t *)idsToSecrets[M->getIdentifier()].c_str(), 
                               errorCode);

        std::cout << "Verifying ..." << std::endl;
        if (!result) {
           std::cout << "verified!\n";
        } else {
           std::cout << "not verified! errorCode: " + errorCode << std::endl;
        }

        // 5. Delete mapping id -> secret. A macaroon is serviced only for
        // one request in this application
        //idsToSecrets.erase (M->getIdentifier());
        //std::cout << "Size of idsToSecrets: " << idsToSecrets.size() << std::endl;

        return result;
      } //verify
 


      void
      onKeyInterest(const InterestFilter& filter, const Interest& interest)
      {
	Name keyName = ndn::Name(m_producerIdentity + "/" + interest.getName().at(4).toUri());

	std::cout << keyName << std::endl;

	std::cout << "<< I Certificate: " << interest << std::endl;


	try {
	  // Create Data packet
	  shared_ptr<IdentityCertificate> cert = 
	    m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(keyName));

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
        const std::string PRODUCER_KSK_NAME = m_princKeyNames[PRODUCER_KSK];
        std::string content;

        Name interestName = interest.getName();

        // Interest Name: /example/producer/<command>/...
        std::string command = interestName.at(COMMAND_POS).toUri();

        if (command == "getMacaroon") {

          std::cout << "Request Macaroon: validating interest..." << std::endl;

          // /example/producer/<command>/<sessionKey>/<INTEREST_SIG_VALUE>/<INTEREST_SIG_INFO>
          m_validator.validate(interest,
                         bind(&Producer::onGetMacaroonValidated, this, _1),
                         bind(&Producer::onValidationFailed, this, _1, _2));

        } else if (command == "deposit" or command == "withdraw") {

          std::cout << "Request Operation: " << command << std::endl;

          // Interest Name: /example/producer/<command>/<sessionKey>/<macaroon>/<dischargeMacaroon>

          // get <sessionKey> and store in the secTpmFile
          ndn::Name session_key_name("/session-key-producer-consumer2");
          getSessionKeyFromInterest(make_shared<Interest>(interest), 
                                    SESSION_KEY_POS, session_key_name);

          shared_ptr<macaroons::NDNMacaroon> M = getMacAndDischargeMacFromInterest(make_shared<Interest>(interest),
                                                                                   MACAROON_POS, session_key_name);

          // Verify operation requested and macaroon caveat
          int result = verify(M.get(), command);
          if (!result) {
            content = std::string("verified!");
          } else {
            content = std::string("not verified!");
          }

          // Prepare and send reply containing the result of the operation 
          // Build Data packet:
          //     name:    interestName/result/version 
          //     content: verified or not verified 
          Name dataName(interest.getName());
          dataName
            .append("result") // add "result" component to Interest name
            .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

          shared_ptr<Data> data = make_shared<Data>();
          data->setName(dataName);
          data->setFreshnessPeriod(time::seconds(0));
          data->setContent(reinterpret_cast<const uint8_t*>(content.c_str()), content.size());

	  m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey(PRODUCER_KSK_NAME));

          std::cout << ">> D: " << *data << std::endl;
          m_face.put(*data);

        } else {
           std::cout << "Interest Command ERROR " << std::endl;
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


      shared_ptr <macaroons::NDNMacaroon>
      getMacAndDischargeMacFromInterest(const shared_ptr <const Interest> & interest, 
                                        const unsigned sessionKeyPos,
                                        const Name session_key_name)
      {
        ndn::SecTpmFileEnc m_secTpmFile;
        // extract <macaroon> from name 
        ndn::name::Component encrypted_macaroon = interest->getName().at(MACAROON_POS);

        // Decrypt macaroon with <sessionKey>
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

        // Create NDNMacaroon
        shared_ptr<macaroons::NDNMacaroon> M = make_shared<macaroons::NDNMacaroon>(std::string(decrypted_macaroon->buf(), 
                   decrypted_macaroon->buf() + decrypted_macaroon->size()));
        std::cout << "Macaroon construido" << std::endl;

        // extract discharge macaroons from name
        std::cout << "*** num third party requests " << M->getNumThirdPartyCaveats() << std::endl;

        for (unsigned i=1; i <= M->getNumThirdPartyCaveats(); i++) {
          // get discharge macaroon (dm)
          ndn::name::Component encrypted_dm = interest->getName().at(MACAROON_POS+i);
          // Decrypt dm
          ndn::ConstBufferPtr decrypted_dm =
            m_secTpmFile.decryptInTpm(encrypted_dm.value(),
                                      encrypted_dm.value_size(),
                                      session_key_name,
                                      /*symmetric*/ true);
          // Bind DischargeMacaroon 
          M->addDischarge(std::string(decrypted_dm->buf(), 
                          decrypted_dm->buf() + decrypted_dm->size()));
          std::cout << "*** added discharge, nms: " << M->getNumDischargeM() << std::endl;
         
        }
        // return macaroon+discharge macaroon built from interest name
        return M;
      }

     
      void
      getSessionKeyFromInterest(const shared_ptr <const Interest> & interest, 
                                const unsigned sessionKeyPos,
                                const Name session_key_name)
      {
        ndn::SecTpmFileEnc m_secTpmFile;

        // Get session_key from interestName
        ndn::name::Component encrypted_session_key = interest->getName().at(sessionKeyPos);

        // Decrypt session_key sent by consummer1, using Producer_DSK key
        ndn::Name producer_DSK_key_name(m_princKeyNames[PRODUCER_DSK]);
        ndn::ConstBufferPtr session_key_bits =
          m_secTpmFile.decryptInTpm(encrypted_session_key.value(),
                                    encrypted_session_key.value_size(),
                                    producer_DSK_key_name,
                                    /*no symmetric*/ false);

        // save session_key_bits with /session-key name inside m_secTpmFile
        m_secTpmFile.setSymmetricKeyToTpm(session_key_name, 
                                        session_key_bits->buf(), 
                                        session_key_bits->size());

        std::cout << "Session key name=" << session_key_name << " added to secTpmFile" << std::endl;
      }
      
      void
      onGetMacaroonValidated(const shared_ptr<const Interest>& interest)
      {
        ndn::SecTpmFileEnc m_secTpmFile;
        const std::string PRODUCER_KSK_NAME = m_princKeyNames[PRODUCER_KSK];

        std::cout << "Validated INTEREST -> Generating macaroon" << std::endl;

        // get session key and store in secTpmFile with session_key_name
        ndn::Name session_key_name("/session-key-producer-consumer1");
        getSessionKeyFromInterest(interest, SESSION_KEY_POS, session_key_name);

 
        // Create macaroon
        std::shared_ptr<macaroons::NDNMacaroon> M = create_macaroon(PRODUCER_PREFIX, 
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


        // Build Data packet:
        //     name:    interestName/result/version 
        //     content: enc(serialized_macaroon)
        Name dataName(interest->getName());
        dataName
            .append("result") // add "result" component to Interest name
            .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

        shared_ptr<Data> data = make_shared<Data>();
        data->setName(dataName);
        data->setFreshnessPeriod(time::seconds(0));
        data->setContent(encrypted_serialized_macaroon);

        // Sign data packet
	m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey(PRODUCER_KSK_NAME));
	
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

      // Interest Name:
      // /example/producer/COMMAND/SESSION_KEY/MACAROON/INTEREST_SIG_VALUE/INTEREST_SIG_INFO

      enum {
        // 0  --> /example
        // 1  --> /producer
        COMMAND_POS         = 2, // Position of command in name: getMacaroon, deposit, withdraw
        SESSION_KEY_POS     = 3, // Position session Key
        MACAROON_POS        = 4, // Position of macaroon in name. 
                                 // Discharge i is in MACAROON_POS + i ...
        INTEREST_SIG_VALUE  = -1,
        INTEREST_SIG_INFO   = -2
      };

      enum princEnum_t {PRODUCER_KSK, PRODUCER_DSK};

      const std::string PRODUCER_PREFIX = "/example/producer";

      // m_producerIdentity is extracted from KEYNAMES_FILENAME
      std::string m_producerIdentity;
      // m_princKeyNames: principal kenames are extracted from KEYNAMES_FILENAME
      std::map<princEnum_t, std::string> m_princKeyNames;

      // Macaroon is created from secret: Map <macaroonId, secret>
      std::map<std::string, std::string> idsToSecrets;

      Face m_face;
      KeyChain m_keyChain;
      ValidatorConfig m_validator;

      // Example caveats
      std::string first_party_caveat_1 = "account = 3735928559";
      std::string first_party_caveat_2 = "time < 2016-02-27 08:22:00";
      std::string first_party_caveat_3 = "email = alice@example.org";
      std::string first_party_caveat_4 = "IP = 127.0.0.1";
      std::string first_party_caveat_5 = "browser = Chrome";
      std::string first_party_caveat_6 = "action = deposit";
      std::string first_party_caveat_7 = "action = withdraw";
      std::string first_party_caveat_8 = "OS = Windows XP";
    };

  } // namespace examples
} // namespace macaroons



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


