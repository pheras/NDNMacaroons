#!/bin/bash

KEYS_PREFIX=/ndn/keys
PRODUCER_ID=producer
CONSUMER1_ID=consumer1
CONSUMER2_ID=consumer2
THIRD_PARTY_ID=thirdParty

ID_LIST="$PRODUCER_ID $CONSUMER1_ID $CONSUMER2_ID $THIRD_PARTY_ID"

for id in $ID_LIST
do
   # KSK Keys
   ndnsec-key-gen $KEYS_PREFIX/$id > /dev/null
   ndnsec-sign-req $KEYS_PREFIX/$id > ./config/${id}-ksk.cert
   ndnsec-cert-install -f ./config/${id}-ksk.cert
   ndnsec-list -kc | grep $KEYS_PREFIX/${id}/ksk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt

   # DSK Keys
   ndnsec-key-gen -d $KEYS_PREFIX/$id > /dev/null
   ndnsec-sign-req $KEYS_PREFIX/$id > ./config/${id}-dsk.cert
   ndnsec-cert-install -f ./config/${id}-dsk.cert
   ndnsec-list -kc | grep $KEYS_PREFIX/${id}/dsk | sed 's/\+->\* //' | sed 's/ *//' >> keys.txt
done

