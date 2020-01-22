# COE817-Project
Secure online voting application

This project implements the secure election protocol described in [SCHN96], p. 127 (Voting with Two Central Facilities). The implementation
provides a secure way for people to vote online to avoid being physically present at designated voting locations.

2 Facilities:
CLA - Central Legitimization Agency - Purpose: Certify the voters
CTF - Central Tabulating Facility - Purpose: Count the votes

Protocol is as follows:
(1) Each voter sends a message to the CLA asking for a validation
number.
(2) The CLA sends the voter back a random validation number. The
CLA maintains a list of validation numbers. The CLA also keeps a list
of the validation numbers’ recipients, in case someone tries to vote
twice.
(3) The CLA sends the list of validation numbers to the CTF.
(4) Each voter chooses a random identification number. He creates a
message with that number, the validation number he received from the
CLA, and his vote. He sends this message to the CTF.
(5) The CTF checks the validation number against the list it received
from the CLA in step (3). If the validation number is there, the CTF
crosses it off (to prevent someone from voting twice). The CTF adds the
identification number to the list of people who voted for a particular
candidate and adds one to the tally.
(6) After all votes have been received, the CTF publishes the outcome,
as well as the lists of identification numbers and for whom their owners
voted.

On startup, the CLA and CTF are created. Each facility will then generate it's own set of RSA public and private keys. The CLA will also
generate a DES symmetric key to be exchanged with the CTF when all voters have been certified.

All voters will interact with the CLA to verify their identity and send their votes. The voters and the CLA will first exchange public 
RSA keys to be able to communicate securely. To ensure that both parties are legitimate, the CLA will send out challenge nonces. If the
responses from the client are not as expected the CLA will terminate the connection. The CLA and Client once verified will then use
their RSA keys to exchange a symmetric DES key which they will use for the rest of the session. The client will then cast their vote and
submit it to the CLA. Their connection will then end. The CLA will also assign each client a unique validation number which will be sent
to the CTF.

Once the CLA has tabulated all the votes, they are sent to the CTF for tabulation. The CLA and CTF will perform the same exchange of 
RSA and DES keys and perform nonce verification. The CLA will then send the votes to the CTF where the results will be calculated.
