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
    class AccessTokenSignerTest < Minitest::Test
      def test_generate_token_signature_returns_valid_signature
        signer = VirgilAccessTokenSigner.new
        crypto = VirgilCrypto.new
        key_pair = crypto.generate_keys
        token_bytes = Bytes.from_string('AAAA.BBBB.CCCC')
        signature = signer.generate_token_signature(token_bytes, key_pair.private_key)
        assert_equal(true, signer.verify_token_signature(signature, token_bytes, key_pair.public_key))
      end

      def test_verify_token_signature_with_wrong_key_returns_false
        crypto = VirgilCrypto.new
        key_pair1 = crypto.generate_keys
        key_pair2 = crypto.generate_keys
        signer = VirgilAccessTokenSigner.new

        token_bytes = Bytes.from_string('AAAA.BBBB.CCCC')
        signature = signer.generate_token_signature(token_bytes, key_pair1.private_key)
        assert_equal(false, signer.verify_token_signature(signature, token_bytes, key_pair2.public_key))
      end
    end
  end
end