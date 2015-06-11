#include "e_macaroon.pb.h"

#include <ndn-cxx/util/time.hpp>
#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include <boost/regex.hpp>


#include <NDNMacaroon/macaroon.hpp>
#include <NDNMacaroon/macaroon-utils.hpp>
#include <NDNMacaroon/sec-tpm-file-enc.hpp>


const unsigned NUM_RETRIES = 20;

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
  // Additional nested namespace could be used to prevent/limit name contentions
  namespace examples {

    std::string hint_shared_key_third_party;

    
    class Consumer : noncopyable
    {
    public:

      Consumer()
      {
	//     0          1            2        3     4
	// /example/thirdParty/setSharedSecret/id/encryptedSharedSecret
	Name interestName("/example/thirdParty/setSharedSecret");

	// uint8_t id[4];
	// ndn::SecTpmFileEnc m_secTpmFile;
	// m_secTpmFile.generateRandomBlock(id, 4);
	// hint_shared_key_third_party = std::string(id, id+4);
	hint_shared_key_third_party = "zxcvb"; // identifies consumer1

	interestName.append(hint_shared_key_third_party);

	ndn::Name session_key_name(hint_shared_key_third_party);
	const unsigned SESSION_KEY_SIZE = 32; // is 32 bytes enough. Check it.
	// public key of third party
	ndn::Name public_key_name("/ndn/keys/karen/dsk-1428573423700");
	ndn::ConstBufferPtr enc_session_key = 
	  macaroons::generateSessionKey(public_key_name, session_key_name, SESSION_KEY_SIZE);
	  
	// append encrypted session key to interest name
	interestName.append(ndn::name::Component(enc_session_key));
	  
	  
	Interest newInterest(interestName);
          
	newInterest.setInterestLifetime(time::milliseconds(1000));
	newInterest.setMustBeFresh(true);

	m_keyChain.sign(newInterest, m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/alice/ksk-1427110059198"));
	  
	unsigned retries = NUM_RETRIES;        
	m_face.expressInterest
	  (newInterest,
	   bind(&Consumer::onSetSharedSecretData, 
		this, 
		_1,  
		_2),
	   bind(&Consumer::onTimeout, this, _1, retries));

      }

      ~Consumer()
      {
      }

      void
      run()
      {
        // Generate session key
        const unsigned SESSION_KEY_SIZE = 32; // is 32 bytes enough. Check it.
        ndn::Name public_key_name("/ndn/keys/bob/dsk-1428573298310");
        session_key_name =  Name("/session-key-consumer1-producer");
        ndn::ConstBufferPtr enc_session_key =
          macaroons::generateSessionKey(public_key_name, session_key_name, SESSION_KEY_SIZE);

        // InterestName = getMacaroon + encrypted session key
        Name interestName("/example/producer/getMacaroon");
        interestName.append(ndn::name::Component(enc_session_key));

        // Create Interest 
        Interest interest(interestName);
        interest.setInterestLifetime(time::milliseconds(1000));
        interest.setMustBeFresh(true);

        // sign interest
        // m_keyChain.setDefaultKeyNameForIdentity("/ndn/keys/alice/ksk-1427110059198");
        // m_keyChain.signByIdentity(interest, Name("/ndn/keys/alice"));
	m_keyChain.sign(interest, m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/alice/ksk-1427110059198"));

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
      onSetSharedSecretData(const Interest& interest, const Data& data)
      {
        std::string content =
          std::string(data.getContent().value(), 
                      data.getContent().value() + data.getContent().value_size());

	std::cout << "setSharedSecret done" << std::endl;
	std::cout << data.getName() << std::endl;

      }// onData


      void
      onData(const Interest& interest, const Data& data)
      {
        std::string content =
          std::string(data.getContent().value(), 
                      data.getContent().value() + data.getContent().value_size());

        std::string command = data.getName().at(2).toUri();
        // Valid commnads: [ getMacaroon | third-party-location | withdraw | deposit ]

        if (command == "getMacaroon") {
   
          ndn::SecTpmFileEnc m_secTpmFile;
          std::cout << "Received macaroon from producer" << std::endl;

          // Received macarron,
          // when consumer2 request macaroon, then, third party caveats will be added

          // Decrypt data content
          ndn::ConstBufferPtr decrypted_content =
            m_secTpmFile.decryptInTpm(data.getContent().value(),
                                      data.getContent().value_size(),
                                      session_key_name,
                                      /*symmetric*/ true);


          content = std::string(decrypted_content->buf(),
                                decrypted_content->buf() + decrypted_content->size());

          m = make_shared<macaroons::NDNMacaroon>(content);        

          std::cout << data.getName() << std::endl;

          m_face.setInterestFilter("/example/consumer1",
                                 bind(&Consumer::onMacaroonInterest, this, _1, _2),
                                 RegisterPrefixSuccessCallback(),
                                 bind(&Consumer::onRegisterFailed, this, _1, _2));

        }
      }// onData
      
      void
      onTimeout(const Interest& interest, unsigned retries)
      {
        retries--;

        if (retries != 0)
          m_face.expressInterest(interest,
                                 bind(&Consumer::onData, this,  _1, _2),
                                 bind(&Consumer::onTimeout, this, _1, retries));          
        
        std::cout << "Timeout " << " retries: " << retries << "  " << interest  << std::endl;
      } //onTimeout

      void 
      onMacaroonInterest(const InterestFilter& filter, const Interest& interest)
      {
        const unsigned COMMAND_POS  = 2; // Position of command in name.
        ndn::SecTpmFileEnc m_secTpmFile;
       
        Name interestName = interest.getName();

        std::string command = interestName.at(COMMAND_POS).toUri();

        if (command == "getMacaroon") {
          std::string content;
          std::cout << "Validated INTEREST -> Generating macaroon with third party caveats" << std::endl;
 
          //
          // add third party caveats
          //
          uint8_t caveat_key_buf[MACAROON_SUGGESTED_SECRET_LENGTH];

          shared_ptr<macaroons::NDNMacaroon> newM = make_shared<macaroons::NDNMacaroon>(m->serialize());


          // m_secTpmFile.generateRandomBlock(caveat_key_buf, MACAROON_SUGGESTED_SECRET_LENGTH);
          // newM->addThirdPartyCaveat("/example/thirdParty/getDischargeMacaroon/" + hint_shared_key_third_party,
	  // 			    "user==jim",
	  // 			    caveat_key_buf,
	  // 			    bind(macaroons::encryptIdentifier, _1, _2, _3, true, hint_shared_key_third_party, &m_secTpmFile));
	  
          m_secTpmFile.generateRandomBlock(caveat_key_buf, MACAROON_SUGGESTED_SECRET_LENGTH);
          newM->addThirdPartyCaveat("/example/thirdParty/getDischargeMacaroon/" + hint_shared_key_third_party,
	  			    "group==friendsOfJuly",
	  			    caveat_key_buf,
	  			    bind(macaroons::encryptIdentifier, _1, _2, _3, true, hint_shared_key_third_party, &m_secTpmFile));
	  
          m_secTpmFile.generateRandomBlock(caveat_key_buf, MACAROON_SUGGESTED_SECRET_LENGTH);
          newM->addThirdPartyCaveat("/example/thirdParty/getDischargeMacaroon/" + hint_shared_key_third_party,
	  			    "group==friendsOfAlice",
	  			    caveat_key_buf,
	  			    bind(macaroons::encryptIdentifier, _1, _2, _3, true, hint_shared_key_third_party, &m_secTpmFile));
	  
	  



	  //
	  // Create protobuf e_macaroon message: macaroon, [endorsement]
	  //


	  // 1. macaroon newM->serialize()
	  macaroons::e_macaroon e_macaroon;
	  e_macaroon.set_macaroon (newM->serialize());
	  
	  // 2. ksk producer endorsement == (type, name, certname, hash)
	  {
	    macaroons::e_macaroon::Endorsement* endorsement = e_macaroon.add_endorsements();

	    std::cout<<">>>>"<<std::endl;
	    //	    m_keyChain.setDefaultKeyNameForIdentity("/ndn/keys/bob/dsk-1428573298310");
	    shared_ptr<IdentityCertificate> cert = 
	      m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(ndn::Name("/ndn/keys/bob/ksk-1428573187822")));
	    std::cout<<">>>>"<<std::endl;
	    std::stringstream ss;
	    {
	      using namespace CryptoPP;
	      
	      SHA256 hash;
	      StringSource(cert->wireEncode().wire(), cert->wireEncode().size(), true,
	  		   new HashFilter(hash, new FileSink(ss)));
	    }
	    endorsement->set_kind ("ksk");
	    endorsement->set_name(newM->getLocation());
	    // set certname, which doesn't include the version, i.e.,
	    // the last component of the name
	    endorsement->set_certname(cert->getName().getPrefix(-1).toUri());
	    endorsement->set_hash(ss.str());
	  }

	  // 3. dsk producer endorsement == (type, name, certname, hash)
	  {
	    macaroons::e_macaroon::Endorsement* endorsement = e_macaroon.add_endorsements();

	    std::cout<<">>>>"<<std::endl;
	    //	    m_keyChain.setDefaultKeyNameForIdentity("/ndn/keys/bob/dsk-1428573298310");
	    shared_ptr<IdentityCertificate> cert = 
	      m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(ndn::Name("/ndn/keys/bob/dsk-1428573298310")));
	    std::cout<<">>>>"<<std::endl;
	    std::stringstream ss;
	    {
	      using namespace CryptoPP;
	      
	      SHA256 hash;
	      StringSource(cert->wireEncode().wire(), cert->wireEncode().size(), true,
	  		   new HashFilter(hash, new FileSink(ss)));
	    }
	    endorsement->set_kind ("dsk");
	    endorsement->set_name(newM->getLocation());
	    // set certname, which doesn't include the version, i.e.,
	    // the last component of the name
	    endorsement->set_certname(cert->getName().getPrefix(-1).toUri());
	    endorsement->set_hash(ss.str());
	  }



	  // 4. ksk third party endorsement == (type, name, certname, hash)
	  // We should add one third party endorsement for each third party caveat in newM
	  {
	    macaroons::e_macaroon::Endorsement* endorsement = e_macaroon.add_endorsements();
	    shared_ptr<IdentityCertificate> cert = 
	      m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(ndn::Name("/ndn/keys/karen/ksk-1428573427553")));
	    std::stringstream ss;
	    {
	      using namespace CryptoPP;
	      
	      SHA256 hash;
	      StringSource(cert->wireEncode().wire(), cert->wireEncode().size(), true,
	  		   new HashFilter(hash, new FileSink(ss)));
	    }
	    std::string third_party_location;
	    ndn::ConstBufferPtr tp_id_sp;
	    newM->getThirdPartyCaveat(1, third_party_location, &tp_id_sp);

	    endorsement->set_kind("ksk");
	    endorsement->set_name(third_party_location);
	    // set certname, which doesn't include the version, i.e.,
	    // the last component of the name
	    endorsement->set_certname(cert->getName().getPrefix(-1).toUri());
	    endorsement->set_hash(ss.str());
	  }

	  // 5. dsk third party endorsement == (type, name, certname, hash)
	  {
	    macaroons::e_macaroon::Endorsement* endorsement = e_macaroon.add_endorsements();

	    std::cout<<">>>>"<<std::endl;
	    shared_ptr<IdentityCertificate> cert = 
	      m_keyChain.getCertificate(m_keyChain.getDefaultCertificateNameForKey(ndn::Name("/ndn/keys/karen/dsk-1428573423700")));
	    std::cout<<">>>>"<<std::endl;
	    std::stringstream ss;
	    {
	      using namespace CryptoPP;
	      
	      SHA256 hash;
	      StringSource(cert->wireEncode().wire(), cert->wireEncode().size(), true,
	  		   new HashFilter(hash, new FileSink(ss)));
	    }
	    std::string third_party_location;
	    ndn::ConstBufferPtr tp_id_sp;
	    newM->getThirdPartyCaveat(1, third_party_location, &tp_id_sp);

	    endorsement->set_kind ("dsk");
	    endorsement->set_name(third_party_location);
	    // set certname, which doesn't include the version, i.e.,
	    // the last component of the name
	    endorsement->set_certname(cert->getName().getPrefix(-1).toUri());
	    endorsement->set_hash(ss.str());
	  }




          // Create new name, based on Interest's name
          Name dataName(interest.getName());
          dataName
            .append("result") // add "result" component to Interest name
            .appendVersion();  // add "version" component (current UNIX timestamp in milliseconds)

	  std::cout << "Enviando datos firmados" << std::endl;
       
	  shared_ptr<Data> data = make_shared<Data>();
	  data->setName(dataName);
	  data->setFreshnessPeriod(time::seconds(0));

	  OBufferStream os;
	  e_macaroon.SerializeToOstream(&os);
	  data->setContent(os.buf());

	  // m_keyChain.setDefaultKeyNameForIdentity("/ndn/keys/alice/ksk-1427110059198");
	  // m_keyChain.signByIdentity(*data, Name("/ndn/keys/alice"));
	  m_keyChain.sign(*data, m_keyChain.getDefaultCertificateNameForKey("/ndn/keys/alice/ksk-1427110059198"));

	  std::cout << ">> D: " << *data << std::endl;
	  m_face.put(*data);


       } else {
           std::cout << "Not supported interest" << std::endl;
       }
     } //onMacaroonInterest


    
     void
     onRegisterFailed(const Name& prefix, const std::string& reason)
      {
        std::cerr << "ERROR: Failed to register prefix \""
                  << prefix << "\" in local hub's daemon (" << reason << ")"
                  << std::endl;
        m_face.shutdown();
      } //onRegisterFailed



    private:
      Face m_face;
      KeyChain m_keyChain;
      shared_ptr<macaroons::NDNMacaroon> m;
      Name session_key_name;
    };

  } // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{

  ndn::examples::Consumer consumer;
  try {
    for (int i = 1; i <= 100000; i++)
      consumer.run();
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
  }
  return 0;
}
