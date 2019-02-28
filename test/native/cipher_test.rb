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
    class CipherTest < Minitest::Test
      def test_encrypts_and_decrypts_data
        raw_data = Bytes.from_string("test")
        key_pair1 = Core::VirgilKeyPair.generate(
          Core::VirgilKeyPair::Type_FAST_EC_ED25519
        )
        key_pair2 = Core::VirgilKeyPair.generate(
          Core::VirgilKeyPair::Type_FAST_EC_ED25519
        )
        cipher = Core::VirgilCipher.new
        cipher.add_key_recipient(Bytes.from_string("1"), key_pair1.public_key)
        cipher.add_key_recipient(Bytes.from_string("2"), key_pair2.public_key)
        encrypted_data = cipher.encrypt(raw_data, true)
        cipher = Core::VirgilCipher.new
        decrypted_data1 = cipher.decrypt_with_key(
          encrypted_data,
          Bytes.from_string("1"),
          key_pair1.private_key
        )
        assert_equal(
          raw_data,
          decrypted_data1
        )
        decrypted_data2 = cipher.decrypt_with_key(
          encrypted_data,
          Bytes.from_string("2"),
          key_pair2.private_key
        )
        assert_equal(
          raw_data,
          decrypted_data2
        )
      end
    end
  end
end
