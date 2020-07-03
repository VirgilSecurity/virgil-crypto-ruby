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
    class CompatibilityTest < Minitest::Test
      def setup
        @crypto = VirgilCrypto.new
        @crypto.use_SHA256_fingerprints = true
      end

      def test_encrypt_single_recipient
        data = compatibility_data["encrypt_single_recipient"]
        private_key = @crypto.import_private_key(data["private_key"])
        decrypted_data = @crypto.decrypt(data["cipher_data"], private_key)
        assert_equal(data["original_data"], decrypted_data)
      end

      def test_encrypt_multiple_recipients
        data = compatibility_data["encrypt_multiple_recipients"]
        data["private_keys"].each do |pk|
          private_key = @crypto.import_private_key(pk)
          decrypted_data = @crypto.decrypt(data["cipher_data"], private_key)
          assert_equal(data["original_data"], decrypted_data)
        end
      end

      def test_sign_then_encrypt_single_recipient
        data = compatibility_data["sign_then_encrypt_single_recipient"]
        private_key = @crypto.import_private_key(data["private_key"])
        public_key = @crypto.extract_public_key(private_key)
        decrypted_data = @crypto.decrypt_then_verify(
            data["cipher_data"],
            private_key,
            public_key
        )
        assert_equal(data["original_data"], decrypted_data)
      end


      def test_sign_then_encrypt_multiple_recipients
        data = self.compatibility_data["sign_then_encrypt_multiple_recipients"]
        private_keys = data["private_keys"].map do |pk|
          @crypto.import_private_key(pk)
        end

        public_key = @crypto.extract_public_key(private_keys[0])
        private_keys.each do |private_key|
          decrypted_data = @crypto.decrypt_then_verify(
              data["cipher_data"],
              private_key,
              public_key
          )
          assert_equal(data["original_data"], decrypted_data)
        end
      end

      def test_generate_signature
        data = self.compatibility_data["generate_signature"]
        private_key = @crypto.import_private_key(data["private_key"])
        signature = @crypto.generate_signature(data["original_data"], private_key)
        assert_equal(data["signature"], signature)
        public_key = @crypto.extract_public_key(private_key)
        assert(
            @crypto.verify_signature(data["signature"], data["original_data"], public_key)
        )
      end

      def compatibility_data
        @compatibility_data ||= decode_data(TestData.compatibility_data)
      end

      def decode_data(data)
        case data
        when Hash
          data.each_with_object({}) {|(k,v), acc| acc[k] = decode_data(v) }
        when Array
          data.map {|v| decode_data(v) }
        when String
          Bytes.from_base64(data)
        else
          data
        end
      end
    end
  end
end