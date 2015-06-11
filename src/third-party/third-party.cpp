#include <set>
#include <string>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/cryptopp.hpp>
#include <ndn-cxx/util/time.hpp>
#include <ndn-cxx/security/validator-config.hpp>


#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>


/************** Macaroon declarations ****************/
namespace macaroons{

  std::string first_party_caveat_1 = "account = 3735928559";
  std::string first_party_caveat_2 = "time < 2016-02-27 08:22:00";
  std::string first_party_caveat_3 = "email = alice@example.org";
  std::string first_party_caveat_4 = "IP = 127.0.0.1";
  std::string first_party_caveat_5 = "browser = Chrome";
  std::string first_party_caveat_6 = "action = deposit";
  std::string first_party_caveat_7 = "action = withdraw";
  std::string first_party_caveat_8 = "OS = Windows XP";

  /* returns serialized macaroon */
  std::string
  create_discharge_macaroon (std::string third_party_location, uint8_t *caveat_key, 
                             uint8_t *identifier, size_t identifier_size)
  {
    // From identifier we should look for stored caveat_key, or it
    // should have been provided, encrypted, in request.  We have it
    // hardwired now (must be the same that was added by producer to
    // third party caveat!

    std::cout << "caveat_key: "
              << std::string (caveat_key, caveat_key + MACAROON_SUGGESTED_SECRET_LENGTH) 
              << std::endl 
              << identifier 
              << std::endl;

    macaroons::NDNMacaroon D(third_party_location, caveat_key, 
                             identifier, identifier_size);
    
    D.addFirstPartyCaveat(first_party_caveat_2);

    return D.serialize();
  }// create_discharge_macaroon


}// namespace macaroons




/*
 *
 *
 *
 *
 */



// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
  // Additional nested namespace could be used to prevent/limit name contentions
  namespace examples {

    std::string FILENAME="./config/validation-third-party.conf";

    class ThirdParty : noncopyable
    {
    public:

      ThirdParty(): m_validator(m_face)
      {

	// Fill table of authenticator
	keyNameToUser["/ndn/keys/jim/ksk-1428573527782"] = "jim";
	groupNameToUsers["friendsOfAlice"].insert("jim");
	groupNameToUsers["friendsOfJuly"].insert("jim");

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

      ~ThirdParty()
      {
      }

      void
      run()
      {
        m_face.setInterestFilter("/example/thirdParty/getDischargeMacaroon",
                                 bind(&ThirdParty::onInterest, this, _1, _2),
                                 RegisterPrefixSuccessCallback(),
                                 bind(&ThirdParty::onRegisterFailed, this, _1, _2));
	m_face.setInterestFilter("/ndn/keys/karen",
				 bind(&ThirdParty::onKeyInterest, this, _1, _2),
				 RegisterPrefixSuccessCallback(),
				 bind(&ThirdParty::onRegisterFailed, this, _1, _2));
	m_face.setInterestFilter("/example/thirdParty/setSharedSecret",
				 bind(&ThirdParty::onSetSharedSecret, this, _1, _2),
				 RegisterPrefixSuccessCallback(),
				 bind(&ThirdParty::onRegisterFailed, this, _1, _2));


        m_face.processEvents();
      }

      enum {
        // 0 --> /example
        // 1 --> /thirdParty
        COMMAND_POS     = 2,
	HINT            = 3,
        ID_POS          = 4,
        SESSION_KEY_POS = 5
      };

    private:
      void
      getSessionKeyFromInterest(const shared_ptr <const Interest>& interest,
                    const unsigned sessionKeyPos,
                    const Name session_key_name)
      {
        ndn::SecTpmFileEnc m_secTpmFile;

        std::cout << "getSessionKeyFromInterest" <<  std::endl;

        // Get session_key from interestName
        ndn::name::Component encrypted_session_key = interest->getName().at(sessionKeyPos);

        // Decrypt session_key sent by consummer, using karen private key
        ndn::Name pub_key_name("/ndn/keys/karen/dsk-1428573423700");
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

      } // getSessionKeyFromInterest


      void
      onSetSharedSecret (const InterestFilter& filter, const Interest& interest)
      {
        
        std::cout << "<< I: " << interest << std::endl;
        
        std::string content;

        // Interest Name = Third party location + encode(third party id)
        // Third party location should be /<any>/<any>/getDischargeMacaroon

        if (interest.getName().at(COMMAND_POS).toUri() != "setSharedSecret") 
           return;


        std::cout << "Validating interest..." << std::endl;
        m_validator.validate(interest,
                             bind(&ThirdParty::onValidatedSetSharedSecret, this, _1),
                             bind(&ThirdParty::onValidationFailed, this, _1, _2));

      }

      void
      onKeyInterest(const InterestFilter& filter, const Interest& interest)
      {
	Name keyName = ndn::Name("/ndn/keys/karen/" + interest.getName().at(4).toUri());
	std::cout << "<< I Certificate: " << interest << std::endl;

	try {
	  // Create Data packet
	  shared_ptr<IdentityCertificate> cert = 
	    m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(keyName));

	  // Return Data packet to the requester
	  std::cout << ">> CERTIFICATE: " << *cert << std::endl;
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
        
        std::cout << "<< I: " << interest << std::endl;
        
        std::string content;

        // Interest Name = Third party location + encode(third party id)
        // Third party location should be /<any>/<any>/getDischargeMacaroon

        if (interest.getName().at(COMMAND_POS).toUri() != "getDischargeMacaroon") 
           return;


        std::cout << "Validating interest..." << std::endl;
        m_validator.validate(interest,
                             bind(&ThirdParty::onValidatedgetDischargeMacaroon, this, _1),
                             bind(&ThirdParty::onValidationFailed, this, _1, _2));
      } // onInterest


      bool
      checkPredicate(const std::string& predicate, const shared_ptr<const Interest>& interest){
	// Authentication
	//
	// extract keylocator from signature of interest
	//

	const Name& interestName = interest->getName();
	Signature signature(interestName[signed_interest::POS_SIG_INFO].blockFromValue(),
			    interestName[signed_interest::POS_SIG_VALUE].blockFromValue());

	if (!signature.hasKeyLocator())
	  return false;

	const KeyLocator& keyLocator = signature.getKeyLocator();
	
	if (keyLocator.getType() != KeyLocator::KeyLocator_Name)
	  return false;
	
	Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocator.getName());
	
	// types of predicate: user==username group==groupName
	std::cout << "PREDICATE: " << predicate << std::endl;
	size_t posPred = predicate.find("::", MACAROON_SUGGESTED_SECRET_LENGTH);
	size_t pos = predicate.find("==", MACAROON_SUGGESTED_SECRET_LENGTH);

	std::string typePredicate = predicate.substr(MACAROON_SUGGESTED_SECRET_LENGTH+2, pos-posPred-2);
	std::cout<< "typePredicate: " << typePredicate << std::endl;

	if (typePredicate == "user"){
	  std::string userName = predicate.substr(pos + 2);
	  std::cout << "userName: " << userName << std::endl;
	  std::cout << "keyName: " << keyName << std::endl;


	  if (keyNameToUser[keyName.toUri()] == userName)
	    return true;
	  else
	    return false;
	}
	else if (typePredicate == "group"){
	  std::string groupName = predicate.substr(pos + 2);
	  std::cout << "groupName: " << groupName << std::endl;
	  std::cout << "keyName: " << keyName << std::endl;
	  std::string userName = keyNameToUser[keyName.toUri()];

	  // now find userName in set groupNameToUsers[groupName]
	  if (groupNameToUsers[groupName].find(userName) != groupNameToUsers[groupName].end())
	    return true;
	  else 
	    return false;
	}
	else
	  return false;
	
      }// checkPredicate

      void
      onValidatedSetSharedSecret(const shared_ptr<const Interest>& interest)
      {
	//     0          1            2            3                       4
	// /example/thirdParty/setSharedSecret/hint_shared_secret/encryptedSharedSecret

        std::cout << "Validated!!!" << std::endl;

        ndn::Name session_key_name(interest->getName()[3].toUri());
	getSessionKeyFromInterest(interest->shared_from_this(),
				  4,
				  session_key_name);

	std::cout << "onSetSharedSecret: " << session_key_name << std::endl;



	// Create new name, based on Interest's name
	Name dataName(interest->getName());
	// Create Data packet
	shared_ptr<Data> data = make_shared<Data>();
	dataName
	  .append("setSharedSecret")
	  .appendVersion();  
	data->setName(dataName);
	data->setFreshnessPeriod(time::seconds(2));
        // Sign Data packet with default identity
	m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/karen/ksk-1428573427553"));
        m_face.put(*data);

      }// onValidatedSetSharedSecret

      void
      onValidatedgetDischargeMacaroon(const shared_ptr<const Interest>& interest)
      {
        ndn::SecTpmFileEnc m_secTpmFile;

        std::cout << "Validated!!!" << std::endl;

	// interest.getName() == third_party_location/third_party_id/enc_session_key
	// where third_party_location includes in last component the hint for third party


        // Interest which requests dischargeMacaroon
        std::string location = interest->getName().getPrefix(4).toUri();

        std::cout << "LLOCATION="  << location << std::endl;
        std::cout << "LLOCATION="  << location << std::endl;    



	ndn::Name session_key_consumer1_third_party(interest->getName()[HINT].toUri());
	std::cout << "LLOCATION="  << location << std::endl;            



        ndn::name::Component identifier = interest->getName().at(ID_POS);



        // get session_key
        ndn::Name session_key_name("session-key-consumer2-third-party");
        getSessionKeyFromInterest(interest, SESSION_KEY_POS, session_key_name);



        std::cout << "ºººº identifier: " 
                  << std::string(identifier.value(),identifier.value() + identifier.value_size()) 
                  << std::endl;


        ndn::ConstBufferPtr c =  
          m_secTpmFile.decryptInTpm(reinterpret_cast<const uint8_t*>(identifier.value()), 
				    identifier.value_size(), 
				    session_key_consumer1_third_party,
				    true);

        std::string caveat_keyPredicate = std::string(c->buf(), c->buf() + c->size());

        std::cout << "id plain: " << std::string(c->buf(), c->buf() + c->size()) << std::endl;
        std::cout << "predicate: " 
                  << std::string(c->buf() + MACAROON_SUGGESTED_SECRET_LENGTH + 2, c->buf() + c->size()) 
                  << std::endl;



	// Create new name, based on Interest's name
	Name dataName(interest->getName());
	
	// Create Data packet
	shared_ptr<Data> data = make_shared<Data>();
	
	bool authenticated = checkPredicate(caveat_keyPredicate, interest);
	if (authenticated) {
	  // create discharge macaroon 
	  std::string serialize_disMacaroon = 
	    macaroons::create_discharge_macaroon(location,
						 (uint8_t*)c->buf(),
						 (uint8_t*)identifier.value(),
						 identifier.value_size());
	  // encrypt discharge macaroon
	  ndn::ConstBufferPtr encrypted_serialized_disMacaroon =
	    m_secTpmFile.encryptInTpm((uint8_t*) serialize_disMacaroon.c_str(),
				      serialize_disMacaroon.size(),
				      session_key_name,
				      true  /* symmetric */);
	  
	  dataName
	    .append("authenticated") // add "result" component to Interest name
	    .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)
	  data->setContent(encrypted_serialized_disMacaroon);
	}
	else { // not authenticated
	  // Create new name, based on Interest's name

	  dataName
	    .append("unauthenticated") // add "result" component to Interest name
	    .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)
	}
	
	data->setName(dataName);
	data->setFreshnessPeriod(time::seconds(2));

        // Sign Data packet with default identity
	// m_keyChain.setDefaultKeyNameForIdentity("/ndn/keys/karen/ksk-1428573427553");
	// m_keyChain.signByIdentity(*data, Name("/ndn/keys/karen"));
	m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/karen/ksk-1428573427553"));

        // Return Data packet to the requester
        std::cout << ">> D: " << *data << std::endl;
        m_face.put(*data);

      } // onValidatedgetDischargeMacaroon

      void
      onValidationFailed(const shared_ptr<const Interest>& interest, const std::string& failureInfo)
      {
        std::cerr << "Not validated INTEREST " << interest->getName()
                  << ". The failure info: " << failureInfo << std::endl;
      }



      void
      onRegisterFailed(const Name& prefix, const std::string& reason)
      {
        std::cerr << "ERROR: Failed to register prefix \""
                  << prefix << "\" in local hub's daemon (" << reason << ")"
                  << std::endl;
        m_face.shutdown();

      } // onRegisterFailed


    private:
      Face m_face;
      KeyChain m_keyChain;
      ValidatorConfig m_validator;

      std::map<std::string, std::string> keyNameToUser;
      std::map<std::string, std::set<std::string> > groupNameToUsers;

      
    };
    
  } // namespace examples
} // namespace ndn



int
main(int argc, char** argv)
{


  ndn::examples::ThirdParty thirdParty;
  try {
    thirdParty.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}


