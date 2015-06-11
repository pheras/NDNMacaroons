#include <validator-panel.hpp>
#include "e_macaroon.pb.h"

#include <ndn-cxx/security/cryptopp.hpp>
#include <ndn-cxx/security/key-chain.hpp>

#include <ndn-cxx/util/time.hpp>
#include <ndn-cxx/face.hpp>


#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>
#include <NDNMacaroon/sec-tpm-file-enc.hpp>




const unsigned NUM_RETRIES = 1;

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
  // Additional nested namespace could be used to prevent/limit name contentions
  namespace examples {

    
    class Consumer : noncopyable
    {
    public:
      void
      run()
      {
        std::cout << "Interest /example/consumer1/getMacaroon" << std::endl;

        Interest interest(Name("/example/consumer1/getMacaroon"));
        interest.setInterestLifetime(time::milliseconds(1000));
        interest.setMustBeFresh(true);


        unsigned retries = NUM_RETRIES;        
        m_face.expressInterest(interest,
                               bind(&Consumer::onData, this,  _1, _2),
                               bind(&Consumer::onTimeout, this, _1, retries));

        std::cout << "Sending " << interest << std::endl;

        // processEvents will block until the requested data received or timeout occurs
        m_face.processEvents();
      }

    private:

      void
      macaroonReadyForRequest(shared_ptr<macaroons::NDNMacaroon> M)
      {
        SecTpmFileEnc m_secTpmFile;

        std::cout << "Requesting service with macaroon + discarge macaroon=" 
                  << M->getNumDischargeM() << std::endl;

        // Generate session key
        const unsigned SESSION_KEY_SIZE = 32; // is 32 bytes enough. Check it.

	std::cout << "M->getLocation() " << M->getLocation() << std::endl;
	ndn::Name public_key_name(secureChannels[M->getLocation()]);
	//        ndn::Name public_key_name("/ndn/keys/bob/dsk-1428573298310");
	ndn::Name session_key_name =  Name("/session-key-consumer2-producer");
        ndn::ConstBufferPtr enc_session_key =
          macaroons::generateSessionKey(public_key_name, session_key_name, SESSION_KEY_SIZE);

        // InterestName = deposit + encrypted session key + macaroon + discharged macaroons

        // Add deposit + encrypted session key
        Name interestName(M->getLocation() + "/deposit");
        interestName.append(ndn::name::Component(enc_session_key));

        // Add encrypted serialized macaroon 
        std::string serialized_macaroon = M->serialize();
        ndn::ConstBufferPtr encrypted_serialized_macaroon =
          m_secTpmFile.encryptInTpm((uint8_t*) serialized_macaroon.c_str(),
                                  serialized_macaroon.size(),
                                  session_key_name,
                                  true  /* symmetric */);

         interestName.append(ndn::name::Component(encrypted_serialized_macaroon));

        
        // Add one component for each encrypted discharge macaroon
        for (unsigned i=1; i <= M->getNumDischargeM(); i++) {
          std::string serialized_dischargeMacaroon = M->getDischargeMacaroon(i);
          ndn::ConstBufferPtr encrypted_serialized_dischargeMacaroon =
            m_secTpmFile.encryptInTpm((uint8_t*) serialized_dischargeMacaroon.c_str(),
                                  serialized_dischargeMacaroon.size(),
                                  session_key_name,
                                  true  /* symmetric */);
            interestName.append(ndn::name::Component(encrypted_serialized_dischargeMacaroon));
        }
        
        Interest newInterest(interestName);
        
        newInterest.setInterestLifetime(time::milliseconds(1000));
        newInterest.setMustBeFresh(true);

        unsigned retries = NUM_RETRIES;        
        m_face.expressInterest(newInterest,
                               bind(&Consumer::onData, this,  _1, _2),
                               bind(&Consumer::onTimeout, this, _1, retries));
      } // macaroonReadyForRequest


      void 
      onValidatedThirdPartyData(const shared_ptr<const Data>& data,                        
				ndn::Name& session_key_name,
				void (Consumer::*onDone)(shared_ptr<macaroons::NDNMacaroon>), shared_ptr<macaroons::NDNMacaroon> M)
      {
        SecTpmFileEnc m_secTpmFile;

	if (data->getName()[-2].toUri() == "authenticated") {
	  std::cout << "authenticated!" << std::endl;
	  
	  // Decrypt data content
	  ndn::ConstBufferPtr decrypted_content =
	    m_secTpmFile.decryptInTpm(data->getContent().value(),
				      data->getContent().value_size(),
				      session_key_name,
                                      /*symmetric*/ true);
	  
	  std::string dm = std::string(decrypted_content->buf(),
				       decrypted_content->buf() + decrypted_content->size());
	  
	  // prepare and store discharge macaroon
	  M->addDischargeAndPrepare(dm);
	  
	  // If we have all the discharge macaroons, send request
	  if (M->getNumDischargeM() == M->getNumThirdPartyCaveats()){
	    (this->*onDone)(M);
	  }
	}
	else
	  std::cout << "NOT authenticated!" << std::endl;
      }


      void 
      onValidationFailedThirdPartyData(const shared_ptr<const Data>& data, const std::string& failureInfo)
      {
	std::cerr << "onValidationFailedThirdPartyData" 
	  //		  << ". The failure info: " << failureInfo 
		  << std::endl;
      }


      void
      onThirdPartyData(shared_ptr<macaroons::NDNMacaroon> M,
                       /*const Interest& interest,*/ 
                       const Data& data,
		       ndn::Name& session_key_name,
                       void (Consumer::*onDone)(shared_ptr<macaroons::NDNMacaroon> M)
                       )
      {
	m_validator.validate(data,
			     bind(&Consumer::onValidatedThirdPartyData, this, _1, session_key_name, onDone, M),
			     bind(&Consumer::onValidationFailedThirdPartyData, this, _1, _2));
	
      }// onThirdPartyData


      void processThirdPartyCaveats (macaroons::e_macaroon& e_macaroon)
      {
	std::cout << "processThirdPartyCaveats ()" << std::endl;
	// get macaroon from extended macaroon
	std::string serializedMacaroon = e_macaroon.macaroon();
	
	// unserialize macaroon
	shared_ptr<macaroons::NDNMacaroon> m = 
	  make_shared<macaroons::NDNMacaroon>(serializedMacaroon);        
	
	std::cout << m->getNumThirdPartyCaveats() << std::endl;
	
	// process third party caveats, if any, of received Macaroon
	for (unsigned i = 1; i <= m->getNumThirdPartyCaveats(); i++){
	  std::cout << "*********************************************" << std::endl;
	  std::cout << "*** process third party" << std::endl;
	  
	  std::string third_party_location;
	  
	  ndn::ConstBufferPtr tp_id_sp;
	  m->getThirdPartyCaveat(i, third_party_location, &tp_id_sp);
	  
	  std::cout << "third_party_location: " << third_party_location << std::endl;
          
	  /* Send request for discharge to third-party:
	     Format of interest name: 
	     third_party_location/third_party_id/enc_session_key
	     where third_party_location includes in last component the hint for third party
	  */
	  Name interestName(third_party_location);
	  interestName.append(ndn::name::Component(*tp_id_sp));
	  std::cout << "processing third party: " << third_party_location << std::endl;

	  ndn::Name public_key_name(secureChannels[third_party_location]);
	  //ndn::Name public_key_name("/ndn/keys/karen/dsk-1428573423700");
	  ndn::Name session_key_name(std::string("/session-key-consumer") + std::string("-") + std::to_string(i));
	  const unsigned SESSION_KEY_SIZE = 32; // is 32 bytes enough. Check it.
	  ndn::ConstBufferPtr enc_session_key = 
	    macaroons::generateSessionKey(public_key_name, session_key_name, SESSION_KEY_SIZE);
	  
	  // append encrypted session key to interest name
	  interestName.append(ndn::name::Component(enc_session_key));
	  
	  
	  std::cout << "     " << "INTEREST NAME: " << interestName << std::endl;
	  
	  Interest newInterest(interestName);
          
	  newInterest.setInterestLifetime(time::milliseconds(1000));
	  newInterest.setMustBeFresh(true);

	  // sign interest
	  // m_keyChain.setDefaultKeyNameForIdentity("/ndn/keys/jim/ksk-1428573527782");
	  // m_keyChain.signByIdentity(newInterest, Name("/ndn/keys/jim"));
	  m_keyChain.sign(newInterest, m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/jim/ksk-1428573527782"));
	  
	  
	  unsigned retries = NUM_RETRIES;        
	  m_face.expressInterest
	    (newInterest,
	     bind(&Consumer::onThirdPartyData, 
		  this, 
		  m,  
		  _2,
		  session_key_name,
		  &Consumer::macaroonReadyForRequest),
	     bind(&Consumer::onTimeout, this, _1, retries));
	  
	}// for
      };// processThirdPartyCaveats()
      

      void
      onEndorseCertificateInternal(const Interest& interest, Data& data, macaroons::e_macaroon& e_macaroon, std::set<std::string>& valid_names, unsigned index)
      {
	std::string kind = e_macaroon.endorsements(index).kind();
	std::string name = e_macaroon.endorsements(index).name();
	std::string certName = e_macaroon.endorsements(index).certname();

	std::cout << "m_rules:: " << std::endl
		  << name << std::endl
		  << certName << std::endl;
	
	std::stringstream ss;
	{
	  using namespace CryptoPP;
	  
	  SHA256 hash;
	  StringSource(data.wireEncode().wire(), data.wireEncode().size(), true,
		       new HashFilter(hash, new FileSink(ss)));
	}
	ndn::Name keyName = ndn::IdentityCertificate::certificateNameToPublicKeyName(certName);
	
	
	if (kind == "ksk") {
	  // Add a rule that can be used by the validator to check that
	  // data packets with *name* are signed with *certName*.  
	  m_validator.addRule(name, certName);
	  
	  if (ss.str() == e_macaroon.endorsements(index).hash()) {
	    // add trust anchor
	    m_validator.addTrustAnchor(keyName, ndn::IdentityCertificate(data).getPublicKeyInfo());
	  }
	} 
	else if (kind == "dsk"){
	  std::cout << "Adding to secureChannels: " << name << std::endl;
	  secureChannels[name] = keyName.toUri();
	  // now we add the key to key chain so we can use it to encrypt
	  std::cout << "dsk keyName: " << keyName << std::endl;

	  if (!m_keyChain.doesPublicKeyExist(keyName))
	    m_keyChain.addKey(keyName, ndn::IdentityCertificate(data).getPublicKeyInfo());
	}

	fetchCertificate(e_macaroon, valid_names, index + 1);
      }
      
      void
      onEndorseCertificateInternalTimeout(const Interest& interest, macaroons::e_macaroon& e_macaroon, std::set<std::string>& valid_names, unsigned index)
      {
      	std::cout << "Can't fetch certificate" <<  interest << std::endl;
	fetchCertificate(e_macaroon, valid_names, index + 1);
      }
      
      void
      fetchCertificate(macaroons::e_macaroon& e_macaroon, std::set<std::string>& valid_names, const int index)
      {
	if (index < e_macaroon.endorsements_size()) {

	  std::string name = e_macaroon.endorsements(index).name();
	  if (valid_names.find(name) != valid_names.end()) {
	    std::string certname = e_macaroon.endorsements(index).certname();
	    
	    Name interestName(certname);

	    Interest interest(interestName);
	    interest.setInterestLifetime(time::milliseconds(1000));
	    interest.setMustBeFresh(true);
   std::cout << "--- " << interest << std::endl;	    
	    m_face.expressInterest(interest,
				   bind(&Consumer::onEndorseCertificateInternal,
					this, _1, _2, e_macaroon, valid_names, index),
				   bind(&Consumer::onEndorseCertificateInternalTimeout,
					this, _1, e_macaroon, valid_names, index));
	  }
	  else
	    fetchCertificate(e_macaroon, valid_names, index + 1);
	}
	else {
	  std::cout << "----" << std::endl;
	  processThirdPartyCaveats (e_macaroon);	
	}
      }// fetchCertificate
      

      void 
      onValidatedProducerData(const shared_ptr<const Data>& data)
				
      {
	std::cout << "onValidatedProducerData" 
		  << std::endl;

	  // get macaroon from Data
	  std::string serializedMacaroon = std::string(data->getContent().value(), data->getContent().value() + data->getContent().value_size());

          // std::cout << "Data name: " << data.getName() << std::endl;
          std::cout 
            << "data received from producer: " 
            << serializedMacaroon
            << std::endl;
      }
      
      void 
      onValidationFailedProducerData(const shared_ptr<const Data>& data, const std::string& failureInfo)
      {
	std::cerr << "onValidationFailedProducerData " 
	  //		  << ". The failure info: " << failureInfo 
		  << std::endl;
      }


      void
      onData(const Interest& interest, const Data& data)
      {
        std::string content =
          std::string(data.getContent().value(), 
                      data.getContent().value() + data.getContent().value_size());

        std::string command = data.getName().at(2).toUri();
        // Valid commnads: [ getMacaroon | third-party-location | withdraw | deposit ]

        if (command == "getMacaroon"){
	  //
	  // Here we should validate with consumer1 key, depending on
	  // the trust model used between consumer2 and consumer1
	  //

	  // extract extended macaroon from data content
	  macaroons::e_macaroon e_macaroon;
	  e_macaroon.ParseFromArray(data.getContent().value(), data.getContent().value_size());
	  

	  if (e_macaroon.endorsements_size() > 0)
	    {
	      std::set<std::string> valid_names;
	      std::string serializedMacaroon = e_macaroon.macaroon();
	      // get name of macaroon and add to valid_names
	      shared_ptr<macaroons::NDNMacaroon> m = 
		make_shared<macaroons::NDNMacaroon>(serializedMacaroon);        
	      valid_names.insert(m->getLocation());
	      
	      // extract locations of third parties and add them to valid_names
	      for (unsigned i = 1; i <= m->getNumThirdPartyCaveats(); i++){
		std::string third_party_location;
		ndn::ConstBufferPtr tp_id_sp;
		m->getThirdPartyCaveat(i, third_party_location, &tp_id_sp);
		valid_names.insert(third_party_location);
	      }
	      fetchCertificate(e_macaroon, valid_names, 0);
	    }
	  else
	    processThirdPartyCaveats (e_macaroon);

        }
        else if (command == "withdraw" || command == "deposit") {
	  m_validator.validate(data,
	  		       bind(&Consumer::onValidatedProducerData, this, _1),
	  		       bind(&Consumer::onValidationFailedProducerData, this, _1, _2));
        }
      }// onData
      
      void
      onTimeout(const Interest& interest, unsigned retries)
      {
        //retries--;

        //if (retries != 0)
           // sign interest
        //  m_face.expressInterest(interest,
        //                         bind(&Consumer::onData, this,  _1, _2),
        //                         bind(&Consumer::onTimeout, this, _1, retries));          
        
	//        std::cout << "Timeout " << " retries: " << retries << "  " << interest  << std::endl;
        std::cout << "Timeout "  << interest  << std::endl;
      }

    private:
      Face m_face;
      chronochat::ValidatorPanel m_validator;
      //      Name session_key_name;
      KeyChain m_keyChain;
      std::map<std::string, std::string> secureChannels;
    };

  } // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{

  // std::cout << ndn::time::toUnixTimestamp(ndn::time::system_clock::now()).count() << std::endl;

  ndn::examples::Consumer consumer;
  try {
      consumer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
