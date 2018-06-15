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


module Virgil
    module Crypto
        # Enumeration containing supported Algorithms
        class HashAlgorithm

          # Exception raised when Unknown Algorithm passed to convertion method
          class UnknownAlgorithmException < StandardError
            def initialize(algorithm)
              @algorithm = algorithm
              super
            end

            def to_s
              "KeyPairType not found: #{@algorithm}"
            end
          end

          MD5 = :MD5
          SHA1 = :SHA1
          SHA224 = :SHA224
          SHA256 = :SHA256
          SHA384 = :SHA384
          SHA512 = :SHA512

          ALGORITHMS_TO_NATIVE = {
            MD5: Crypto::Native::VirgilHash::Algorithm_MD5,
            SHA1: Crypto::Native::VirgilHash::Algorithm_SHA1,
            SHA224: Crypto::Native::VirgilHash::Algorithm_SHA224,
            SHA256: Crypto::Native::VirgilHash::Algorithm_SHA256,
            SHA384: Crypto::Native::VirgilHash::Algorithm_SHA384,
            SHA512: Crypto::Native::VirgilHash::Algorithm_SHA512
          }


          # Converts algorithm enum value to native value
          # @param algorithm [HashAlgorithm] algorithm for conversion.
          # @return [Integer] Native library algorithm id.
          # @raise [UnknownAlgorithmException] if algorithm is not supported.
          def self.convert_to_native(algorithm)
            if ALGORITHMS_TO_NATIVE.has_key?(algorithm)
              return ALGORITHMS_TO_NATIVE[algorithm]
            end
            raise UnknownAlgorithmException(algorithm)
          end
        end
    end
end
