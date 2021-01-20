These test vectors can be used to validate that an implementation conforms to the U-Prove Cryptographic Specification V1.1 Revision 3.

The testvectors_hashing.txt file contains hash formatting test vectors.

The other files contain values of protocol runs with different parameters. The filenames indicate the protocol options:
* "_SG" for the subgroup construction, "_EC" for the elliptic curve construction
* "_Dx" indicates the number of disclosed attributes; x = 0, 2, or 5
* "_lite" indicates a protocol run without pseudonyms and commitments
* "_Device" indicates a Device-protected token

Note that "ie_" values in the files are for the identity escrow extension available from http://www.microsoft.com/uprove.

