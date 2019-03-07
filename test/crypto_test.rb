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
      def setup
        @crypto = VirgilCrypto.new
        @message_bytes = Bytes.from_string('hi')
      end

      def test_generate_hash_generates_non_empty_array
        hash = @crypto.generate_hash(@message_bytes)
        assert(hash)
      end

      def test_decrypt_encrypted_message_returns_equivalent_message
        key_pair = @crypto.generate_keys
        encrypted = @crypto.encrypt(@message_bytes, key_pair.public_key)
        assert_equal(@message_bytes, @crypto.decrypt(encrypted, key_pair.private_key))
      end

      def test_decrypt_encrypted_message_by_generated_from_key_materia_returns_equivalent_message
        key_material = Bytes.from_string('26dfhvnslvdsfkdfvnndsb234q2xrFOuY5EDSAFGCCXHCJSHJAD')
        key_pair = @crypto.generate_keys(key_material: key_material)
        encrypted = @crypto.encrypt(@message_bytes, key_pair.public_key)
        assert_equal(@message_bytes, @crypto.decrypt(encrypted, key_pair.private_key))

      end

      def test_sign_then_encrypt_decrypt_then_verify
        author_key_pair = @crypto.generate_keys
        receivers = [@crypto.generate_keys, @crypto.generate_keys]
        encrypted = @crypto.sign_then_encrypt(@message_bytes, author_key_pair.private_key,
                                              receivers[0].public_key, receivers[1].public_key)
        receivers.each do |receiver|
          decrypted = @crypto.decrypt_then_verify(encrypted, receiver.private_key, author_key_pair.public_key)
          assert_equal(@message_bytes, decrypted)
        end
      end

      def test_decrypt_encrypted_message_with_wrong_key_raises_exception
        alice_key_pair = @crypto.generate_keys
        bob_key_pair = @crypto.generate_keys

        encrypted_for_alice = @crypto.encrypt(@message_bytes, alice_key_pair.public_key)
        assert_raises VirgilCryptoException do
          @crypto.decrypt(encrypted_for_alice, bob_key_pair.private_key)
        end
      end

      def test_generate_signature_returns_valid_signature
        key_pair = @crypto.generate_keys
        signature = @crypto.generate_signature(@message_bytes, key_pair.private_key)
        assert_equal(true, @crypto.verify_signature(signature, @message_bytes, key_pair.public_key))
      end

      def test_generate_stream_signature_returns_valid_signature
        key_pair = @crypto.generate_keys
        stream = StringIO.new(@message_bytes.to_s)
        signature = @crypto.generate_stream_signature(stream, key_pair.private_key)
        stream.rewind
        assert_equal(true, @crypto.verify_stream_signature(signature, stream, key_pair.public_key))
      end

      def test_decrypt_encrypted_stream_returns_equivalent_stream
        key_pair = @crypto.generate_keys
        origin_stream = StringIO.new(@message_bytes.to_s)
        encrypted_stream = StringIO.new
        @crypto.encrypt_stream(origin_stream, encrypted_stream, key_pair.public_key)
        decrypted_stream = StringIO.new

        encrypted_stream.rewind
        @crypto.decrypt_stream(encrypted_stream, decrypted_stream, key_pair.private_key)
        decrypted_message_bytes = Bytes.from_string(decrypted_stream.string)
        assert_equal(@message_bytes, decrypted_message_bytes)
      end

    end
  end
end