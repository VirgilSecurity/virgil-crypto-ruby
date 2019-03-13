# Virgil Security Ruby Crypto Library
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto-ruby.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-crypto-ruby)
[![Gem](https://img.shields.io/gem/v/virgil-crypto.svg)](https://rubygems.org/gems/virgil-crypto)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)
[![Documentation YARD](https://img.shields.io/badge/docs-yard-blue.svg)](https://virgilsecurity.github.io/virgil-crypto-ruby)

### [Introduction](#introduction) | [Library purposes](#library-purposes) | [Usage examples](#usage-examples) | [Installation](#installation) | [Docs](#docs) | [License](#license) | [Contacts](#support)

## Introduction
VirgilCrypto is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and an open-source high-level [cryptographic library](https://github.com/VirgilSecurity/virgil-crypto) that allows you to perform all necessary operations for securely storing and transferring data in your digital solutions. Crypto Library is written in C++ and is suitable for mobile and server platforms.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be encrypted (and passwords will be eliminated). In this world, the days of developers having to raise millions of dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end. Now developers can instead focus on building features that give them a competitive market advantage while end-users can enjoy the privacy and security they increasingly demand.

## Library purposes
* Asymmetric Key Generation
* Encryption/Decryption of data and streams
* Generation/Verification of digital signatures
* PFS (Perfect Forward Secrecy)

## Usage examples

#### Generate a key pair

Generate a Private Key with the default algorithm (EC_X25519):
```ruby
require 'virgil/crypto'
include Virgil::Crypto

crypto = VirgilCrypto.new
key_pair = crypto.generate_keys
```

#### Generate and verify a signature

Generate signature and sign data with a private key:
```ruby
require 'virgil/crypto'
include Virgil::Crypto

crypto = VirgilCrypto.new

# prepare a message
message_to_sign = 'Hello, Bob!'
data_to_sign = Bytes.from_string(message_to_sign)

# generate a signature
signature = crypto.generate_signature(data_to_sign, sender_private_key)
```

Verify a signature with a public key:
```ruby
require 'virgil/crypto'
include Virgil::Crypto

crypto = VirgilCrypto.new

# verify a signature
verified = crypto.verify_signature(signature, data_to_sign, sender_public_key)
```

#### Encrypt and decrypt data

Encrypt Data on a Public Key:

```ruby
require 'virgil/crypto'
include Virgil::Crypto

crypto = VirgilCrypto.new

# prepare a message
message_to_encrypt = 'Hello, Bob!'
data_to_encrypt = Bytes.from_string(message_to_encrypt)

# encrypt the message
encrypted_data = crypto.encrypt(data_to_encrypt, receiver_public_key)
```

Decrypt the encrypted data with a Private Key:
```ruby
require 'virgil/crypto'
include Virgil::Crypto

crypto = VirgilCrypto.new

# prepare data to be decrypted
decrypted_data = crypto.decrypt(encrypted_data, receiver_private_key)

# decrypt the encrypted data using a private key
decrypted_message = Bytes.new(decrypted_data).to_s
```
      
Need more examples? Visit our [developer documentation](https://developer.virgilsecurity.com/docs/how-to#cryptography).

## Installation

TThe Virgil Crypto is provided as a [gem](https://rubygems.org/) named [*virgil-crypto*](https://rubygems.org/gems/virgil-crypto) and available for Ruby 2.1 and newer. The package is distributed via *bundler* package manager.
 
 To install the package use the command below:
 
 ```
 gem install virgil-crypto
 ```
 
 or add the following line to your Gemfile:
 
 ```
 gem 'virgil-crypto', '~> 3.6.3'
 ```
and then run

```
bundle
```
## Docs
- [Crypto Core Library](https://github.com/VirgilSecurity/virgil-crypto)
- [More usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)

## License

This library is released under the [3-clause BSD License](https://github.com/VirgilSecurity/virgil-sdk-javascript/blob/master/LICENSE).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
