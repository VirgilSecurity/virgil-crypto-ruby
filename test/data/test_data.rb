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
require 'json'
module Virgil
  module Crypto
    module TestData
      DATA_DIR = File.expand_path('../', __FILE__)

      class << self
        def compatibility_data
          @_compatibility_data ||= begin
            path = File.join(DATA_DIR, 'crypto_compatibility_data.json')
            raw_data = File.read(path)
            JSON.parse(raw_data)
          end
        end

        def original_data_file_path
          @original_data_file_path ||= File.join(DATA_DIR, 'input.txt')
        end

        def encrypted_data_file_path
          @encrypted_data_file_path ||= File.join(DATA_DIR, 'encrypted.txt')
        end

        def decrypted_data_file_path
          @decrypted_data_file_path ||= File.join(DATA_DIR, 'output.txt')
        end

      end
    end
  end
end