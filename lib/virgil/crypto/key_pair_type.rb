# Copyright (C) 2015-2019 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#   (1) Redistributions of source code must retain the above copyright
#   notice, this list of conditions and the following disclaimer.
#
#   (2) Redistributions in binary form must reproduce the above copyright
#   notice, this list of conditions and the following disclaimer in
#   the documentation and/or other materials provided with the
#   distribution.
#
#   (3) Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, bytes, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

module Virgil
  module Crypto
    # Enumeration containing supported KeyPairTypes
    class KeyPairType
      # Exception raised when Unknown Type passed to convertion method
      class UnknownTypeException < StandardError
        def initialize(key_pair_type)
          @key_pair_type = key_pair_type
          super
        end

        def to_s
          "KeyPairType not found: #{@key_pair_type}"
        end
      end

      Default = :Default
      RSA_2048 = :RSA_2048
      RSA_3072 = :RSA_3072
      RSA_4096 = :RSA_4096
      RSA_8192 = :RSA_8192
      EC_SECP256R1 = :EC_SECP256R1
      EC_SECP384R1 = :EC_SECP384R1
      EC_SECP521R1 = :EC_SECP521R1
      EC_BP256R1 = :EC_BP256R1
      EC_BP384R1 = :EC_BP384R1
      EC_BP512R1 = :EC_BP512R1
      EC_SECP256K1 = :EC_SECP256K1
      EC_CURVE25519 = :EC_CURVE25519
      FAST_EC_X25519 = :FAST_EC_X25519
      FAST_EC_ED25519 = :FAST_EC_ED25519

      TYPES_TO_NATIVE = {
        Default: Core::VirgilKeyPair::Type_FAST_EC_ED25519,
        RSA_2048: Core::VirgilKeyPair::Type_RSA_2048,
        RSA_3072: Core::VirgilKeyPair::Type_RSA_3072,
        RSA_4096: Core::VirgilKeyPair::Type_RSA_4096,
        RSA_8192: Core::VirgilKeyPair::Type_RSA_8192,
        EC_SECP256R1: Core::VirgilKeyPair::Type_EC_SECP256R1,
        EC_SECP384R1: Core::VirgilKeyPair::Type_EC_SECP384R1,
        EC_SECP521R1: Core::VirgilKeyPair::Type_EC_SECP521R1,
        EC_BP256R1: Core::VirgilKeyPair::Type_EC_BP256R1,
        EC_BP384R1: Core::VirgilKeyPair::Type_EC_BP384R1,
        EC_BP512R1: Core::VirgilKeyPair::Type_EC_BP512R1,
        EC_SECP256K1: Core::VirgilKeyPair::Type_EC_SECP256K1,
        EC_CURVE25519: Core::VirgilKeyPair::Type_EC_CURVE25519,
        FAST_EC_X25519: Core::VirgilKeyPair::Type_FAST_EC_X25519,
        FAST_EC_ED25519: Core::VirgilKeyPair::Type_FAST_EC_ED25519,
      }.freeze

      # Converts type enum value to native value
      # @param key_pair_type [Symbol] type id for conversion.
      # @return [Integer] Native library key pair type id.
      # @raise [UnknownTypeException] if type is not supported.
      def self.convert_to_native(key_pair_type)
        if TYPES_TO_NATIVE.key?(key_pair_type)
          return TYPES_TO_NATIVE[key_pair_type]
        end

        raise VirgilCryptoException, key_pair_type
      end
    end
  end
end