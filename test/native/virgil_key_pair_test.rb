# Copyright (C) 2016 Virgil Security Inc.
#
# Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     (1) Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     (2) Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
#     (3) Neither the name of the copyright holder nor the names of its
#     contributors may be used to endorse or promote products derived from
#     this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
require 'test_helper'

module Virgil
  module Crypto
    class VirgilKeyPairTest < Minitest::Test
      def test_generates_keys
        key_pair = Native::VirgilKeyPair.generate(
          Native::VirgilKeyPair::Type_FAST_EC_ED25519
        )
        assert(
          key_pair.public_key
        )
        assert(
          key_pair.private_key
        )
      end

      def test_converts_keys_to_der
        key_pair = Native::VirgilKeyPair.generate(
          Native::VirgilKeyPair::Type_FAST_EC_ED25519
        )
        assert(
          Native::VirgilKeyPair.public_key_to_der(key_pair.public_key)
        )
        assert(
          Native::VirgilKeyPair.private_key_to_der(key_pair.private_key)
        )
      end

      def test_encrypts_and_decrypts_private_key
        password = Bytes.from_string("test")
        key_pair = Native::VirgilKeyPair.generate(
          Native::VirgilKeyPair::Type_FAST_EC_ED25519
        )
        encrypted_private_key = Native::VirgilKeyPair.encrypt_private_key(
          key_pair.private_key,
          password
        )
        decrypted_private_key = Native::VirgilKeyPair.decrypt_private_key(
          encrypted_private_key,
          password
        )
        assert_equal(
          key_pair.private_key,
          decrypted_private_key
        )
      end

      def test_extracts_public_key
        key_pair = Native::VirgilKeyPair.generate(
          Native::VirgilKeyPair::Type_FAST_EC_ED25519
        )
        extracted_public_key = Native::VirgilKeyPair.extract_public_key(
          key_pair.private_key,
          []
        )
        assert_equal(
          key_pair.public_key,
          extracted_public_key
        )
      end
    end
  end
end
