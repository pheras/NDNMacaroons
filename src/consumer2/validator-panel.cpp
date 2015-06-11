/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
/*
 * Copyright (c) 2013, Regents of the University of California
 *                     Yingdi Yu
 *
 * BSD license, See the LICENSE file for more information
 *
 * Author: Yingdi Yu <yingdi@cs.ucla.edu>
 */

#include <ndn-cxx/security/sec-rule-specific.hpp>
#include <ndn-cxx/util/regex.hpp>
#include <ndn-cxx/util/regex/regex-top-matcher.hpp>

#include "validator-panel.hpp"

//#include "logging.h"

namespace chronochat {

using std::vector;

using ndn::CertificateCache;
using ndn::SecRuleRelative;
using ndn::OnDataValidated;
using ndn::OnDataValidationFailed;
using ndn::ValidationRequest;
using ndn::IdentityCertificate;

const shared_ptr<CertificateCache> ValidatorPanel::DEFAULT_CERT_CACHE =
  shared_ptr<CertificateCache>();

ValidatorPanel::ValidatorPanel(int stepLimit,
                               const shared_ptr<CertificateCache> certificateCache)
  : m_stepLimit(stepLimit)
  , m_certificateCache(certificateCache)
{
}

void
ValidatorPanel::addRule(const std::string& name, const std::string& certname)
{
  m_rules[name] = certname;
}
  
void
ValidatorPanel::addTrustAnchor(const Name& keyName, const ndn::PublicKey& key)
{
  m_trustAnchors[keyName] = key;
}

void
ValidatorPanel::removeTrustAnchor(const Name& keyName)
{
  m_trustAnchors.erase(keyName);
}
  
void
ValidatorPanel::cleanTrustAnchor()
{
  m_trustAnchors.clear();
}


void
ValidatorPanel::checkPolicy (const Data& data,
                             int stepCount,
                             const OnDataValidated& onValidated,
                             const OnDataValidationFailed& onValidationFailed,
                             vector<shared_ptr<ValidationRequest> >& nextSteps)
{
  if (m_stepLimit == stepCount) {
    onValidationFailed(data.shared_from_this(),
                       "Reach maximum validation steps: " + data.getName().toUri());
    return;
  }

  const KeyLocator& keyLocator = data.getSignature().getKeyLocator();

  if (keyLocator.getType() != KeyLocator::KeyLocator_Name)
    return onValidationFailed(data.shared_from_this(),
                              "Key Locator is not a name: " + data.getName().toUri());

  // Look for the most specific entry available in m_rules that
  // matches the name of the data packet
  unsigned i = data.getName().size();
  while ("" == m_rules[data.getName().getPrefix(i).toUri()] && i>0)
    i = i-1;

  std::string certNameS = m_rules[data.getName().getPrefix(i).toUri()];
  if ("" == certNameS)
    { 
      // no rule available to check validity of this data packet
      onValidationFailed(data.shared_from_this(),
                         "Cannot verify signature:" + data.getName().toUri());
      return;
    }

  // Compose the rule that should validate this data packet
  ndn::SecRuleSpecific re (ndn::RegexTopMatcher::fromName(data.getName()),
                           ndn::RegexTopMatcher::fromName(ndn::Name(certNameS))); 

  
  const Name& keyLocatorName = keyLocator.getName();

  std::cout << data.getName() << "--" << keyLocatorName << std::endl;

  if (re.satisfy(data.getName(), keyLocatorName)) {
    Name keyName = IdentityCertificate::certificateNameToPublicKeyName(keyLocatorName);

    // Once we've checked the name of the cert signing the data packet
    // is the right one, check that actually data is being signed by
    // this certificate
    if (m_trustAnchors.end() != m_trustAnchors.find(keyName) &&
        Validator::verifySignature(data, data.getSignature(), m_trustAnchors[keyName]))
      onValidated(data.shared_from_this());
    else
      onValidationFailed(data.shared_from_this(),
                         "Cannot verify signature:" + data.getName().toUri());
  }
  else
    onValidationFailed(data.shared_from_this(),
                       "Does not satisfy rule: " + data.getName().toUri());
  
  return;
}

} // namespace chronochat
