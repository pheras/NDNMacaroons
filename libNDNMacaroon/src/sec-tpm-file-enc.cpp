/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2013-2015 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Xingyu Ma <http://www.linkedin.com/pub/xingyu-ma/1a/384/5a8>
 * @author Yingdi Yu <http://irl.cs.ucla.edu/~yingdi/>
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 */


#include <map> // Used for cache of symmetric keys


#include "sec-tpm-file-enc.hpp"

#include <ndn-cxx/encoding/buffer-stream.hpp>

#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>

#include <ndn-cxx/security/cryptopp.hpp>


#include <sys/types.h>
#include <sys/stat.h>

#include <algorithm>

namespace ndn {

using std::string;
using std::ostringstream;
using std::ofstream;

const std::string SecTpmFileEnc::SCHEME("tpm-file");


  std::map<std::string, std::string> keyNamesToSymKeys; // Cache for symmetric keys

class SecTpmFileEnc::Impl
{
public:
  explicit
  Impl(const string& dir)
  {
    if (dir.empty())
      m_keystorePath = boost::filesystem::path(getenv("HOME")) / ".ndn" / "ndnsec-tpm-file";
    else
      m_keystorePath = boost::filesystem::path(dir) / ".ndn" / "ndnsec-tpm-file";

    boost::filesystem::create_directories(m_keystorePath);
  }

  boost::filesystem::path
  transformName(const string& keyName, const string& extension)
  {
    using namespace CryptoPP;
    string digest;
    SHA256 hash;
    StringSource src(keyName,
                     true,
                     new HashFilter(hash,
                                    new Base64Encoder(new CryptoPP::StringSink(digest))));

    boost::algorithm::trim(digest);
    std::replace(digest.begin(), digest.end(), '/', '%');

    return m_keystorePath / (digest + extension);
  }

  string
  maintainMapping(const string& keyName)
  {
    string keyFileName = transformName(keyName, "").string();

    ofstream outfile;
    string dirFile = (m_keystorePath / "mapping.txt").string();

    outfile.open(dirFile.c_str(), std::ios_base::app);
    outfile << keyName << ' ' << keyFileName << '\n';
    outfile.close();

    return keyFileName;
  }

public:
  boost::filesystem::path m_keystorePath;
};


SecTpmFileEnc::SecTpmFileEnc(const string& location)
  : SecTpm(location)
  , m_impl(new Impl(location))
  , m_inTerminal(false)
{
}

SecTpmFileEnc::~SecTpmFileEnc()
{
}

void
SecTpmFileEnc::generateKeyPairInTpm(const Name& keyName, const KeyParams& params)
{
  string keyURI = keyName.toUri();

  if (doesKeyExistInTpm(keyName, KEY_CLASS_PUBLIC))
    throw Error("public key exists");
  if (doesKeyExistInTpm(keyName, KEY_CLASS_PRIVATE))
    throw Error("private key exists");

  string keyFileName = m_impl->maintainMapping(keyURI);

  try
    {
      switch (params.getKeyType())
        {
        case KEY_TYPE_RSA:
          {
            using namespace CryptoPP;

            const RsaKeyParams& rsaParams = static_cast<const RsaKeyParams&>(params);
            AutoSeededRandomPool rng;
            InvertibleRSAFunction privateKey;
            privateKey.Initialize(rng, rsaParams.getKeySize());

            string privateKeyFileName = keyFileName + ".pri";
            Base64Encoder privateKeySink(new FileSink(privateKeyFileName.c_str()));
            privateKey.DEREncode(privateKeySink);
            privateKeySink.MessageEnd();

            RSAFunction publicKey(privateKey);
            string publicKeyFileName = keyFileName + ".pub";
            Base64Encoder publicKeySink(new FileSink(publicKeyFileName.c_str()));
            publicKey.DEREncode(publicKeySink);
            publicKeySink.MessageEnd();

            /*set file permission*/
            chmod(privateKeyFileName.c_str(), 0000400);
            chmod(publicKeyFileName.c_str(), 0000444);
            return;
          }
        case KEY_TYPE_ECDSA:
          {
            using namespace CryptoPP;

            const EcdsaKeyParams& ecdsaParams = static_cast<const EcdsaKeyParams&>(params);

            CryptoPP::OID curveName;
            switch (ecdsaParams.getKeySize())
              {
              case 256:
                curveName = ASN1::secp256r1();
                break;
              case 384:
                curveName = ASN1::secp384r1();
                break;
              default:
                curveName = ASN1::secp256r1();
              }

            AutoSeededRandomPool rng;

            ECDSA<ECP, SHA256>::PrivateKey privateKey;
            DL_GroupParameters_EC<ECP> cryptoParams(curveName);
            cryptoParams.SetEncodeAsOID(true);
            privateKey.Initialize(rng, cryptoParams);

            ECDSA<ECP, SHA256>::PublicKey publicKey;
            privateKey.MakePublicKey(publicKey);
            publicKey.AccessGroupParameters().SetEncodeAsOID(true);

            string privateKeyFileName = keyFileName + ".pri";
            Base64Encoder privateKeySink(new FileSink(privateKeyFileName.c_str()));
            privateKey.DEREncode(privateKeySink);
            privateKeySink.MessageEnd();

            string publicKeyFileName = keyFileName + ".pub";
            Base64Encoder publicKeySink(new FileSink(publicKeyFileName.c_str()));
            publicKey.Save(publicKeySink);
            publicKeySink.MessageEnd();

            /*set file permission*/
            chmod(privateKeyFileName.c_str(), 0000400);
            chmod(publicKeyFileName.c_str(), 0000444);
            return;
          }
        default:
          throw Error("Unsupported key type!");
        }
    }
  catch (KeyParams::Error& e)
    {
      throw Error(e.what());
    }
  catch (CryptoPP::Exception& e)
    {
      throw Error(e.what());
    }
}

void
SecTpmFileEnc::deleteKeyPairInTpm(const Name& keyName)
{
  boost::filesystem::path publicKeyPath(m_impl->transformName(keyName.toUri(), ".pub"));
  boost::filesystem::path privateKeyPath(m_impl->transformName(keyName.toUri(), ".pri"));

  if (boost::filesystem::exists(publicKeyPath))
    boost::filesystem::remove(publicKeyPath);

  if (boost::filesystem::exists(privateKeyPath))
    boost::filesystem::remove(privateKeyPath);
}

shared_ptr<PublicKey>
SecTpmFileEnc::getPublicKeyFromTpm(const Name&  keyName)
{
  string keyURI = keyName.toUri();

  if (!doesKeyExistInTpm(keyName, KEY_CLASS_PUBLIC))
    throw Error("Public Key does not exist");

  ostringstream os;
  try
    {
      using namespace CryptoPP;
      FileSource(m_impl->transformName(keyURI, ".pub").string().c_str(),
                 true,
                 new Base64Decoder(new FileSink(os)));
    }
  catch (CryptoPP::Exception& e)
    {
      throw Error(e.what());
    }

  return make_shared<PublicKey>(reinterpret_cast<const uint8_t*>(os.str().c_str()),
                                os.str().size());
}

std::string
SecTpmFileEnc::getScheme()
{
  return SCHEME;
}

ConstBufferPtr
SecTpmFileEnc::exportPrivateKeyPkcs8FromTpm(const Name& keyName)
{
  OBufferStream privateKeyOs;
  CryptoPP::FileSource(m_impl->transformName(keyName.toUri(), ".pri").string().c_str(), true,
                       new CryptoPP::Base64Decoder(new CryptoPP::FileSink(privateKeyOs)));

  return privateKeyOs.buf();
}

bool
SecTpmFileEnc::importPrivateKeyPkcs8IntoTpm(const Name& keyName, const uint8_t* buf, size_t size)
{
  try
    {
      using namespace CryptoPP;

      string keyFileName = m_impl->maintainMapping(keyName.toUri());
      keyFileName.append(".pri");
      StringSource(buf, size,
                   true,
                   new Base64Encoder(new FileSink(keyFileName.c_str())));
      return true;
    }
  catch (CryptoPP::Exception& e)
    {
      return false;
    }
}

bool
SecTpmFileEnc::importPublicKeyPkcs1IntoTpm(const Name& keyName, const uint8_t* buf, size_t size)
{
  try
    {
      using namespace CryptoPP;

      string keyFileName = m_impl->maintainMapping(keyName.toUri());
      keyFileName.append(".pub");
      StringSource(buf, size,
                   true,
                   new Base64Encoder(new FileSink(keyFileName.c_str())));
      return true;
    }
  catch (CryptoPP::Exception& e)
    {
      return false;
    }
}

Block
SecTpmFileEnc::signInTpm(const uint8_t* data, size_t dataLength,
                      const Name& keyName, DigestAlgorithm digestAlgorithm)
{
  string keyURI = keyName.toUri();

  if (!doesKeyExistInTpm(keyName, KEY_CLASS_PRIVATE))
    throw Error("private key doesn't exists");

  try
    {
      using namespace CryptoPP;
      AutoSeededRandomPool rng;

      //Read public key
      shared_ptr<PublicKey> pubkeyPtr;
      pubkeyPtr = getPublicKeyFromTpm(keyName);

      switch (pubkeyPtr->getKeyType())
        {
          case KEY_TYPE_RSA:
            {
              //Read private key
              ByteQueue bytes;
              FileSource file(m_impl->transformName(keyURI, ".pri").string().c_str(),
                              true, new Base64Decoder);
              file.TransferTo(bytes);
              bytes.MessageEnd();
              RSA::PrivateKey privateKey;
              privateKey.Load(bytes);

              //Sign message
              switch (digestAlgorithm)
                {
                case DIGEST_ALGORITHM_SHA256:
                  {
                    RSASS<PKCS1v15, SHA256>::Signer signer(privateKey);

                    OBufferStream os;
                    StringSource(data, dataLength,
                                 true,
                                 new SignerFilter(rng, signer, new FileSink(os)));

                    return Block(tlv::SignatureValue, os.buf());
                  }
                default:
                  throw Error("Unsupported digest algorithm!");
                }
            }
        case KEY_TYPE_ECDSA:
          {
            //Read private key
            ByteQueue bytes;
            FileSource file(m_impl->transformName(keyURI, ".pri").string().c_str(),
                            true, new Base64Decoder);
            file.TransferTo(bytes);
            bytes.MessageEnd();

            //Sign message
            switch (digestAlgorithm)
              {
              case DIGEST_ALGORITHM_SHA256:
                {
                  ECDSA<ECP, SHA256>::PrivateKey privateKey;
                  privateKey.Load(bytes);
                  ECDSA<ECP, SHA256>::Signer signer(privateKey);

                  OBufferStream os;
                  StringSource(data, dataLength,
                               true,
                               new SignerFilter(rng, signer, new FileSink(os)));

                  uint8_t buf[200];
                  size_t bufSize = DSAConvertSignatureFormat(buf, 200, DSA_DER,
                                                             os.buf()->buf(), os.buf()->size(),
                                                             DSA_P1363);

                  shared_ptr<Buffer> sigBuffer = make_shared<Buffer>(buf, bufSize);

                  return Block(tlv::SignatureValue, sigBuffer);
                }
              default:
                throw Error("Unsupported digest algorithm!");
              }
          }
        default:
          throw Error("Unsupported key type!");
        }
    }
  catch (CryptoPP::Exception& e)
    {
      throw Error(e.what());
    }
}


ConstBufferPtr
SecTpmFileEnc::decryptInTpm(const uint8_t* data, size_t dataLength,
                         const Name& keyName, bool isSymmetric)
{
  // throw Error("SecTpmFileEnc::decryptInTpm is not supported!");
  string keyURI = keyName.toUri();
  if (!isSymmetric)
    {
      if (!doesKeyExistInTpm(keyName, KEY_CLASS_PRIVATE))
        throw Error("private key doesn't exist");

      try{
        using namespace CryptoPP;
        AutoSeededRandomPool rng;

        //Read private key
        ByteQueue bytes;
        FileSource file(m_impl->transformName(keyURI, ".pri").string().c_str(), true, new Base64Decoder);
        file.TransferTo(bytes);
        bytes.MessageEnd();
        RSA::PrivateKey privateKey;
        privateKey.Load(bytes);
        RSAES_PKCS1v15_Decryptor decryptor(privateKey);

        OBufferStream os;
        StringSource(data, dataLength, true, new PK_DecryptorFilter(rng, decryptor, new FileSink(os)));

        return os.buf();
      }
      catch (CryptoPP::Exception& e){
        throw Error(e.what());
      }
    }
  else
    {
      //      throw Error("Symmetric encryption is not implemented!");
      // pheras: Completed code with AES-CFB-Filter.zip from http://www.cryptopp.com/wiki/Advanced_Encryption_Standard

      if (!doesKeyExistInTpm(keyName, KEY_CLASS_SYMMETRIC))
          throw Error("symmetric key doesn't exist");

      try{
          string keyBits;
          //string symKeyFileName = m_impl->transformName(keyURI, ".key");
          //FileSource(symKeyFileName, true, new HexDecoder(new StringSink(keyBits)));
          CryptoPP::FileSource(m_impl->transformName(keyURI, ".key").string().c_str(), 
                               true, 
                               new CryptoPP::HexDecoder(new CryptoPP::StringSink(keyBits)));
          

          // Extract iv from first block
          using CryptoPP::AES;
          string IVBits;
          CryptoPP::StringSource(data, AES::BLOCKSIZE, true, new CryptoPP::StringSink(IVBits));

          //
          // Strange code that uses a random iv to decrypt! We comment it.
          //
          // CryptoPP::AutoSeededRandomPool rnd;
          // byte iv[AES::BLOCKSIZE];
          // rnd.GenerateBlock(iv, AES::BLOCKSIZE);
          //


          // Decrypt from second block to the end (first block includes de random iv)
          CryptoPP::CFB_Mode<AES>::Decryption decryptor;
          decryptor.SetKeyWithIV(reinterpret_cast<const uint8_t*>(keyBits.c_str()), 
                                 keyBits.size(), 
                                 reinterpret_cast<const uint8_t*>(IVBits.c_str()));
          OBufferStream os;
          CryptoPP::StringSource(data + AES::BLOCKSIZE, 
                                 dataLength - AES::BLOCKSIZE, 
                                 true, 
                                 new CryptoPP::StreamTransformationFilter(decryptor,new CryptoPP::FileSink(os)));
          return os.buf();


      }catch (CryptoPP::Exception& e){
          throw Error(e.what());
      }
    }
}

ConstBufferPtr
SecTpmFileEnc::encryptInTpm(const uint8_t* data, size_t dataLength,
                         const Name& keyName, bool isSymmetric)
{
  //throw Error("SecTpmFileEnc::encryptInTpm is not supported!");
  string keyURI = keyName.toUri();

  if (!isSymmetric)
    {
      if (!doesKeyExistInTpm(keyName, KEY_CLASS_PUBLIC))
        throw Error("public key doesn't exist");
      try
        {
          using namespace CryptoPP;
          AutoSeededRandomPool rng;

          //Read private key
          ByteQueue bytes;
          FileSource file(m_impl->transformName(keyURI, ".pub").string().c_str(), true, new Base64Decoder);
          file.TransferTo(bytes);
          bytes.MessageEnd();
          RSA::PublicKey publicKey;
          publicKey.Load(bytes);

          OBufferStream os;
          RSAES_PKCS1v15_Encryptor encryptor(publicKey);

          StringSource(data, dataLength, true, new PK_EncryptorFilter(rng, encryptor, new FileSink(os)));
          return os.buf();
        }
      catch (CryptoPP::Exception& e){
        throw Error(e.what());
      }
    }
  else
    {
      // throw Error("Symmetric encryption is not implemented!");

      // Completed code with AES-CFB-Filter.zip from http://www.cryptopp.com/wiki/Advanced_Encryption_Standard
      if (!doesKeyExistInTpm(keyName, KEY_CLASS_SYMMETRIC))
          throw Error("symmetric key doesn't exist");

      try{

          // Load key
          string keyBits;
          CryptoPP::FileSource(m_impl->transformName(keyURI, ".key").string().c_str(), 
                               true, 
                               new CryptoPP::HexDecoder(new CryptoPP::StringSink(keyBits)));


          // generate new randon iv
          using CryptoPP::AES;
          CryptoPP::AutoSeededRandomPool rng;
          CryptoPP::SecByteBlock iv(0x00, AES::BLOCKSIZE);
          rng.GenerateBlock(iv, AES::BLOCKSIZE);

          CryptoPP::CFB_Mode<AES>::Encryption encryptor;
          encryptor.SetKeyWithIV(reinterpret_cast<const uint8_t*>(keyBits.c_str()), keyBits.size(), iv);

          OBufferStream os;
          // add iv as first block of ciphertext
          CryptoPP::StringSource(iv, iv.size(), true, new CryptoPP::FileSink(os));
          // now add encrypted message
          CryptoPP::StringSource(data, dataLength, true, new CryptoPP::StreamTransformationFilter(encryptor, new CryptoPP::FileSink(os)));

          return os.buf();

      }catch (CryptoPP::Exception& e){
          throw Error(e.what());
      }
    }
}
  

void
SecTpmFileEnc::setSymmetricKeyToTpm(const Name&  keyName, const uint8_t* keybits, size_t key_size) 
{
  string keyUri = keyName.toUri();

  string symKeyFileName = m_impl->transformName(keyUri, ".key").string();

  if (!doesKeyExistInTpm(keyName, KEY_CLASS_SYMMETRIC))
    // Only creates new mapping if it does not exist already
    string keyFileName = m_impl->maintainMapping(keyUri);
  else
    // Give permission to overwrite files
    chmod(symKeyFileName.c_str(), 0000600);


  using namespace CryptoPP;
  StringSource(keybits, key_size, true, new HexEncoder(new FileSink(symKeyFileName.c_str())));
  
  chmod(symKeyFileName.c_str(), 0000400);
  
  return;

}


  
void
SecTpmFileEnc::getSymmetricKeyFromTpm(const Name&  keyName, std::string& keyBits)
{
    string keyURI = keyName.toUri();
    CryptoPP::FileSource(m_impl->transformName(keyURI, ".key").string().c_str(), true, new CryptoPP::HexDecoder(new CryptoPP::StringSink(keyBits)));
}



void
SecTpmFileEnc::generateSymmetricKeyInTpm(const Name& keyName, const KeyParams& params)
{
  // throw Error("SecTpmFileEnc::generateSymmetricKeyInTpm is not supported!");

  string keyURI = keyName.toUri();

  if (doesKeyExistInTpm(keyName, KEY_CLASS_SYMMETRIC))
    throw Error("symmetric key exists");

  string keyFileName = m_impl->maintainMapping(keyURI);
  string symKeyFileName = keyFileName + ".key";

  try{
    switch (params.getKeyType()){
        case KEY_TYPE_AES:
          {
            using namespace CryptoPP;
            AutoSeededRandomPool rng;

            int keySize = 16; // This constant should be get from params
                              // 16 is one of the valid key sizes for AES

            SecByteBlock key(0x00, keySize);
            rng.GenerateBlock(key, keySize);

            // add to cache
            keyNamesToSymKeys[keyURI] = std::string(key.BytePtr(), key.BytePtr() + key.size());


            StringSource(key, key.size(), true, new HexEncoder(new FileSink(symKeyFileName.c_str())));

            chmod(symKeyFileName.c_str(), 0000400);

            return;
          }
    default:
      throw Error("Unsupported symmetric key type!");
    }
  }catch (CryptoPP::Exception& e){
    throw Error(e.what());
  }
}

bool
SecTpmFileEnc::doesKeyExistInTpm(const Name& keyName, KeyClass keyClass)
{
  string keyURI = keyName.toUri();
  if (keyClass == KEY_CLASS_PUBLIC)
    {
      if (boost::filesystem::exists(m_impl->transformName(keyURI, ".pub")))
        return true;
      else
        return false;
    }
  if (keyClass == KEY_CLASS_PRIVATE)
    {
      if (boost::filesystem::exists(m_impl->transformName(keyURI, ".pri")))
        return true;
      else
        return false;
    }
  if (keyClass == KEY_CLASS_SYMMETRIC)
    {
      if (boost::filesystem::exists(m_impl->transformName(keyURI, ".key")))
        return true;
      else
        return false;
    }
  return false;
}

bool
SecTpmFileEnc::generateRandomBlock(uint8_t* res, size_t size)
{
  try
    {
      CryptoPP::AutoSeededRandomPool rng;
      rng.GenerateBlock(res, size);
      return true;
    }
  catch (CryptoPP::Exception& e)
    {
      return false;
    }
}

} // namespace ndn

