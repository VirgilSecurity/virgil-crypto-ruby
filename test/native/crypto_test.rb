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

require 'test_helper'
module Virgil
  module Crypto
    class CryptoTest < Minitest::Test
      def test_generate_hash_generates_non_empty_array
        crypto = VirgilCrypto.new
        hash = crypto.generate_hash(Bytes.from_string('hi'))
        assert(hash)
      end

      def test_decrypt_encrypted_message_returns_equivalent_message
        crypto = VirgilCrypto.new
        key_pair = crypto.generate_keys
        message_bytes = Bytes.from_string('hi')
        encrypted = crypto.encrypt(message_bytes, key_pair.public_key)
        assert_equal(message_bytes, crypto.decrypt(encrypted, key_pair.private_key))
      end

      def test_decrypt_encrypted_message_by_generated_from_key_materia_returns_equivalent_message
        crypto = VirgilCrypto.new
        key_material = Bytes.from_string('26dfhvnslvdsfkdfvnndsb234q2xrFOuY5EDSAFGCCXHCJSHJAD')
        key_pair = crypto.generate_keys(key_material: key_material)
        message_bytes = Bytes.from_string('hi')
        encrypted = crypto.encrypt(message_bytes, key_pair.public_key)
        assert_equal(message_bytes, crypto.decrypt(encrypted, key_pair.private_key))

      end

      def test_decrypt_encrypted_message_with_wrong_key_raises_exception
        crypto = VirgilCrypto.new
        alice_key_pair = crypto.generate_keys
        bob_key_pair = crypto.generate_keys

        message_bytes = Bytes.from_string('hi')
        encrypted_for_alice = crypto.encrypt(message_bytes, alice_key_pair.public_key)
        assert_raises VirgilCryptoException do
          crypto.decrypt(encrypted_for_alice, bob_key_pair.private_key)
        end
      end

      def test_generate_signature_returns_valid_signature
        crypto = VirgilCrypto.new
        key_pair = crypto.generate_keys
        message_bytes = Bytes.from_string('some card snapshot')
        signature = crypto.generate_signature(message_bytes, key_pair.private_key)
        assert_equal(true, crypto.verify_signature(signature, message_bytes, key_pair.public_key))
      end
    end
  end
end