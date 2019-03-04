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
    class PrivateKeyExporterTest < Minitest::Test
      def test_import_private_key_returns_equivalent_exported_private_key
        exporter = VirgilPrivateKeyExporter.new
        crypto = VirgilCrypto.new
        key_pair = crypto.generate_keys
        exported = exporter.export_private_key(key_pair.private_key)
        imported = exporter.import_private_key(exported)
        assert_equal(key_pair.private_key, imported)
      end

      def test_import_private_key_returns_equivalent_exported_private_key2
        exporter = VirgilPrivateKeyExporter.new(password: 'password')
        wrong_exporter  = VirgilPrivateKeyExporter.new(password: 'wrong password')
        crypto = VirgilCrypto.new
        key_pair = crypto.generate_keys
        exported = exporter.export_private_key(key_pair.private_key)
        assert_raises VirgilCryptoException do
          wrong_exporter.import_private_key(exported)
        end
      end
    end
  end
end