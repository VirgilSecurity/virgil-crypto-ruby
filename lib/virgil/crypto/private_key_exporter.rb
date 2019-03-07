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
    # Provides export [PrivateKey] into its material representation bytes and
    # import [PrivateKey] from its material representation bytes.
    class VirgilPrivateKeyExporter
      attr_reader :virgil_crypto
      attr_reader :password

      # Initializes a new instance of the [VirgilPrivateKeyExporter] class.
      # @param password [String] private key password, nil by default.
      # @param crypto the instance of [Crypto::VirgilCrypto]
      # that is used for export and import of [PrivateKey]
      def initialize(crypto: nil, password: nil)
        @password = password
        @virgil_crypto = crypto || VirgilCrypto.new
      end

      # Exports the provided [PrivateKey] into material representation bytes.
      # @param private_key [PrivateKey] The private key.
      # @return [Crypto::Bytes] Private key material representation bytes.
      def export_private_key(private_key)
        @virgil_crypto.export_private_key(private_key, @password)
      end

      # Imports the private key from its material representation.
      # @param private_key_bytes [Crypto::Bytes] private key material.
      # @return [VirgilPrivateKey] Imported private key.
      def import_private_key(private_key_bytes)
        @virgil_crypto.import_private_key(private_key_bytes, @password)
      end
    end
  end
end