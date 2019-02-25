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
    # Provides a cryptographic operations in applications, such as signature generation
    # and verification in an access token.
    class VirgilAccessTokenSigner


      # Represents used signature algorithm.
      attr_reader :algorithm

      # Initializes a new instance of the [VirgilAccessTokenSigner] class.
      def initialize
        @virgil_crypto = VirgilCrypto.new
        @algorithm = 'VEDS512'
      end

      # Generates the digital signature for the specified token_bytes
      #  using the specified [VirgilPrivateKey]
      # @param token_bytes [Bytes] The material representation bytes of access token
      # for which to compute the signature.
      # @param private_key [VirgilPrivateKey] The digital signature for the material representation
      # bytes of access token.
      # @return The digital signature for the material representation bytes of access token.
      def generate_token_signature(token_bytes, private_key)
        @virgil_crypto.generate_signature(token_bytes, private_key)
      end

      # Verifies that a digital signature is valid by checking the signature,
      # provided public_key and token_bytes
      # @param signature [Bytes] The digital signature for the token_bytes
      # @param token_bytes [Bytes] The material representation bytes of access token
      # for which the signature has been generated.
      # @param public_key [VirgilPublicKey] public
      # key for verification.
      # @return [Boolean] True if signature is valid, False otherwise.
      def verify_token_signature(signature, token_bytes, public_key)
        @virgil_crypto.verify_signature(signature, token_bytes, public_key)
      end

      private

      attr_reader :virgil_crypto
    end
  end
end