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

require 'base64'
require 'json'

module Virgil
  module Crypto
    class Bytes < Array
      # Initializes a new array of bytes from specified string, which encodes binary data.
      # @param str [String] String to decode.
      # @param encoding [VirgilStringEncoding] The character encoding of string.
      # @raise [ArgumentError] if encoding is undefined
      def self.from_string(str, encoding = VirgilStringEncoding::UTF8)
        case encoding
        when VirgilStringEncoding::BASE64
          from_base64(str)
        when VirgilStringEncoding::HEX
          from_hex(str)
        when VirgilStringEncoding::UTF8
          from_utf8(str)
        else
          raise ArgumentError, 'Encoding is undefined'
        end
      end

      # Decodes the current bytes to a string according to the specified
      # character encoding.
      # @param encoding [VirgilStringEncoding] The character encoding to encode to.
      #    equivalent string representation if raw bytes in selected encoding.
      # @return [String]
      # @raise [ArgumentError] if encoding is undefined
      def to_string(encoding = VirgilStringEncoding::UTF8)
        case encoding
        when VirgilStringEncoding::BASE64
          to_base64
        when VirgilStringEncoding::HEX
          to_hex
        when VirgilStringEncoding::UTF8
          to_s
        else
          raise ArgumentError, 'Encoding is undefined'
        end
      end

      # Converts all the bytes to its equivalent string representation in utf8.
      def to_s
        pack('c*')
      end

      # Initializes a new array of bytes from specified string,
      # which encodes binary data as base-64 digits.
      def self.from_base64(str)
        new(Base64.decode64(str).bytes)
      end

      # Initializes a new array of bytes from specified string,
      # which encodes binary data as utf8.
      def self.from_utf8(str)
        new(str.bytes)
      end

      # Initializes a new array of bytes from specified string,
      # which encodes binary data as hexadecimal digits.
      def self.from_hex(str)
        new(str.scan(/../).map { |x| x.hex })
      end

      # Converts all the bytes to its equivalent string representation that
      # is encoded with base-64 digits.
      def to_base64
        Base64.strict_encode64(to_s)
      end

      # Encodes all the bytes into a utf8 string.
      def to_utf8
        to_s
      end

      # Converts the numeric value of each element of a current array of bytes to its
      # equivalent hexadecimal string representation.
      def to_hex
        to_s.unpack('H*').first
      end

    end

    module VirgilStringEncoding
      BASE64 = 1
      HEX = 2
      UTF8 = 3
    end
  end
end