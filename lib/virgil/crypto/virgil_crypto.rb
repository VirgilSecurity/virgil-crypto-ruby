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
    # Wrapper for cryptographic operations.
    #
    # Class provides a cryptographic operations in applications, such as
    # hashing, signature generation and verification, and encryption
    # and decryption
    class VirgilCrypto
      include Virgil::Crypto

      attr_reader :default_key_type
      attr_accessor :use_SHA256_fingerprints
      private :default_key_type

      def initialize(key_pair_type = KeyPairType::Default)
        @default_key_type = key_pair_type
      end

      # Exception raised when Signature is not valid
      class SignatureIsNotValid < StandardError
        def to_s
          'Signature is not valid'
        end
      end

      CUSTOM_PARAM_KEY_SIGNATURE = Crypto::Bytes.from_string(
        'VIRGIL-DATA-SIGNATURE'
      )

      CUSTOM_PARAM_KEY_SIGNER_ID = Crypto::Bytes.from_string(
        'VIRGIL-DATA-SIGNER-ID'
      )

      # Generates asymmetric key pair that is comprised of both public
      # and private keys by specified type.
      # @param keys_type [Symbol] type of the generated keys.
      #   The possible values can be found in KeyPairType enum.
      # @param key_material [Crypto::Bytes] the only data to be used for
      # key generation, length must be more than 31.
      # @return [KeyPair] Generated key pair.
      # @example
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      def generate_keys(keys_type = @default_key_type, key_material = nil)
        begin
          native_type = KeyPairType.convert_to_native(keys_type)
          native_key_pair = nil
          if (!key_material.is_a?(Array) || key_material.empty?)
            native_key_pair = Native::VirgilKeyPair.generate(native_type)
          else
            native_key_pair = Native::VirgilKeyPair.generate_from_key_material(native_type, key_material)
          end
          key_pair_id = compute_public_key_hash(native_key_pair.public_key)
          private_key = VirgilPrivateKey.new(
              key_pair_id,
              wrap_bytes(
                  Native::VirgilKeyPair.private_key_to_der(
                      native_key_pair.private_key
                  )
              )
          )
          public_key = VirgilPublicKey.new(
              key_pair_id,
              wrap_bytes(
                  Crypto::Native::VirgilKeyPair.public_key_to_der(
                      native_key_pair.public_key
                  )
              )
          )
          return KeyPair.new(private_key, public_key)
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Imports the Private key from material representation.
      # @param key_bytes [Crypto::Bytes] private key material
      # representation bytes.
      # @param password [String] private key password, nil by default.
      # @return [VirgilPrivateKey] Imported private key.
      # @example
      #   private_key = crypto.import_private_key(exported_private_key)
      # @see #export_private_key How to get exported_private_key
      def import_private_key(key_bytes, password = nil)
        if !key_bytes.is_a?(Array) || key_bytes.empty?
          raise ArgumentError.new("key_bytes is not valid")
        end
        begin
          decrypted_private_key = if !password
                                    Crypto::Native::VirgilKeyPair.private_key_to_der(key_bytes)
                                  else
                                    Crypto::Native::VirgilKeyPair.decrypt_private_key(
                                        key_bytes,
                                        Crypto::Bytes.from_string(password)
                                    )
                                  end

          public_key_bytes = Crypto::Native::VirgilKeyPair.extract_public_key(
              decrypted_private_key, []
          )
          key_pair_id = compute_public_key_hash(public_key_bytes)
          private_key_bytes = Crypto::Native::VirgilKeyPair.private_key_to_der(
              decrypted_private_key
          )
          return VirgilPrivateKey.new(key_pair_id, wrap_bytes(private_key_bytes))
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end

      end

      # Imports the Public key from material representation.
      # @param key_bytes [Crypto::Bytes] public key material
      # representation bytes.
      # @return [VirgilPublicKey] Imported public key.
      # @example
      #   public_key = crypto.import_public_key(exported_public_key)
      # @see #export_public_key How to get exported_public_key
      def import_public_key(key_bytes)
        if !key_bytes.is_a?(Array) || key_bytes.empty?
          raise ArgumentError.new("key_bytes is not valid")
        end

        begin
          key_pair_id = compute_public_key_hash(key_bytes)
          public_key_bytes = Native::VirgilKeyPair.public_key_to_der(key_bytes)
          VirgilPublicKey.new(key_pair_id, wrap_bytes(public_key_bytes))
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Exports the Private key into material representation.
      # @param private_key [VirgilPrivateKey] private key for export.
      # @param password [String] private key password, nil by default.
      # @return [Crypto::Bytes] Private key material representation bytes.
      # @example
      # crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      # alice_keys = crypto.generate_keys
      # exported_private_key = crypto.export_private_key(alice_keys.private_key)
      def export_private_key(private_key, password = nil)
        if !private_key.is_a?(VirgilPrivateKey)
          raise ArgumentError.new("private_key is not valid")
        end
        begin
          unless password
            return Native::VirgilKeyPair.private_key_to_der(
                private_key.raw_key
            )
          end
          password_bytes = Crypto::Bytes.from_string(password)
          private_key_bytes = Native::VirgilKeyPair.encrypt_private_key(
              private_key.raw_key,
              password_bytes
          )
          wrap_bytes(
              Native::VirgilKeyPair.private_key_to_der(
                  private_key_bytes,
                  password_bytes
              )
          )
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Exports the Public key into material representation.
      # @param public_key [VirgilPublicKey] public key for export.
      # @return [Crypto::Bytes] Key material representation bytes.
      # @example
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      #   exported_public_key = crypto.export_public_key(alice_keys.public_key)
      def export_public_key(public_key)
        if !public_key.is_a?(VirgilPublicKey)
          raise ArgumentError.new("public_key is not valid")
        end
        begin
          wrap_bytes(
              Native::VirgilKeyPair.public_key_to_der(public_key.raw_key)
          )
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Extracts the Public key from Private key.
      # @param private_key [VirgilPrivateKey] source private
      # key for extraction.
      # @return  [VirgilPublicKey] Exported public key.
      def extract_public_key(private_key)
        if !private_key.is_a?(VirgilPrivateKey)
          raise ArgumentError.new("private_key is not valid")
        end

        begin
          public_key_bytes = Crypto::Native::VirgilKeyPair.extract_public_key(
              private_key.raw_key,
              []
          )
          VirgilPublicKey.new(
              private_key.id,
              wrap_bytes(
                  Native::VirgilKeyPair.public_key_to_der(public_key_bytes)
              )
          )
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Encrypts the specified bytes using Public keys.
      # @param bytes [Virgil::Crypto::Bytes] raw data bytes for encryption.
      # @param *public_keys [Array<VirgilPublicKey>] list
      # of public_keys' public keys.
      # @return [Crypto::Bytes] Encrypted bytes.
      # @example
      #   # Data encryption using ECIES scheme with AES-GCM.
      #   # There can be more than one recipient.
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      #   plain_data = Virgil::Crypto::Bytes.from_string('Hello Bob!')
      #   cipher_data = crypto.encrypt(plain_data, alice_keys.public_key)
      # @see #generate_keys
      def encrypt(bytes, *public_keys)
        if !bytes.is_a?(Array) || bytes.empty?
          raise ArgumentError.new("bytes is not valid")
        end

        begin
          cipher = Native::VirgilCipher.new
          public_keys.each do |public_key|
            cipher.add_key_recipient(public_key.id, public_key.raw_key)
          end
          wrap_bytes(cipher.encrypt(bytes, true))
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Decrypts the specified bytes using Private key.
      # @param cipher_bytes [Crypto::Bytes] encrypted data bytes for decryption.
      # @param private_key [VirgilPrivateKey] private key for decryption.
      # @return [Crypto::Bytes] Decrypted data bytes.
      # @example
      #   # You can decrypt data using your private key
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      #   plain_data = crypto.decrypt(cipher_data, alice_keys.private_key)
      # @see #generate_keys
      # @see #encrypt How to get cipher_data
      def decrypt(cipher_bytes, private_key)
        if !cipher_bytes.is_a?(Array) || cipher_bytes.empty?
          raise ArgumentError.new("cipher_bytes is not valid")
        end
        if !private_key.is_a?(VirgilPrivateKey)
          raise ArgumentError.new("private_key is not valid")
        end

        begin
          cipher = Native::VirgilCipher.new
          decrypted_bytes = cipher.decrypt_with_key(
              cipher_bytes,
              private_key.id,
              private_key.raw_key
          )
          wrap_bytes(decrypted_bytes)
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Signs and encrypts the data.
      # @param bytes [Crypto::Bytes] data bytes for signing and encryption.
      # @param private_key [VirgilPrivateKey] private key to sign the data.
      # @param *public_keys [Array<VirgilPublicKey>] list of public keys
      #   used for data encryption.
      # @return [Crypto::Bytes] Signed and encrypted data bytes.
      # @example
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #
      #   alice = crypto.generate_keys
      #   bob = crypto.generate_keys
      #
      #   # The data to be signed with alice's Private key
      #   data = Virgil::Crypto::Bytes.from_string('Hello Bob, How are you?')
      #   cipher_data = crypto.sign_then_encrypt(
      #     data,
      #     alice.private_key,
      #     bob.public_key
      #   )
      def sign_then_encrypt(bytes, private_key, *public_keys)
        if !bytes.is_a?(Array) || bytes.empty?
          raise ArgumentError.new("bytes is not valid")
        end

        if !private_key.is_a?(VirgilPrivateKey)
          raise ArgumentError.new("private_key is not valid")
        end

        begin
          signer = Crypto::Native::VirgilSigner.new(HashAlgorithm::SHA512)
          signature = signer.sign(bytes, private_key.raw_key)
          cipher = Crypto::Native::VirgilCipher.new
          custom_bytes = cipher.custom_params
          custom_bytes.set_data(
              CUSTOM_PARAM_KEY_SIGNATURE,
              signature
          )

          public_key = extract_public_key(private_key)
          custom_bytes.set_data(
              CUSTOM_PARAM_KEY_SIGNER_ID,
              wrap_bytes(public_key.id)
          )

          public_keys.each do |public_key|
            cipher.add_key_recipient(public_key.id, public_key.raw_key)
          end
          wrap_bytes(cipher.encrypt(bytes))
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Decrypts and verifies the data.
      # @param bytes [Crypto::Bytes] encrypted data bytes.
      # @param private_key [VirgilPrivateKey] private key for decryption.
      # @param *public_keys [Array<VirgilPublicKey>] a list of public keys
      # for verification,
      #   which can contain signer's public key.
      # @return [Crypto::Bytes] Decrypted data bytes.
      # @raise [SignatureIsNotValid] if signature is not verified.
      # @example
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #
      #   alice = crypto.generate_keys
      #   bob = crypto.generate_keys
      #
      #   decrypted_data = crypto.decrypt_then_verify(
      #     cipher_data,
      #     bob.private_key,
      #     alice.public_key
      #   )
      # @see #sign_then_encrypt How to get cipher_data
      def decrypt_then_verify(bytes, private_key, *public_keys)

        if !bytes.is_a?(Array) || bytes.empty?
          raise ArgumentError.new("bytes is not valid")
        end

        if !private_key.is_a?(VirgilPrivateKey)
          raise ArgumentError.new("private_key is not valid")
        end

        begin
          cipher = Crypto::Native::VirgilCipher.new
          decrypted_bytes = cipher.decrypt_with_key(
              bytes,
              private_key.id,
              private_key.raw_key
          )
          signature = cipher.custom_params.get_data(CUSTOM_PARAM_KEY_SIGNATURE)

          signer_public_key = public_keys.first
          if public_keys.count > 1
            signer_id = cipher.custom_params.get_data(CUSTOM_PARAM_KEY_SIGNER_ID)

            signer_public_key = public_keys.find {|public_key| public_key.id == signer_id}

          end

          is_valid = verify_signature(decrypted_bytes, signature, signer_public_key)
          unless is_valid
            raise VirgilCryptoException.new('Signature is not valid')
          end
          wrap_bytes(decrypted_bytes)
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Signs the specified data using Private key.
      # @param bytes [Crypto::Bytes] raw data bytes for signing.
      # @param private_key [VirgilPrivateKey] private key for signing.
      # @return [Crypto::Bytes] Signature data.
      # @example Sign the SHA-384 fingerprint of bytes using your private key.
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   # The data to be signed with alice's Private key
      #   data = Virgil::Crypto::Bytes.from_string('Hello Bob, How are you?')
      #   signature = crypto.generate_signature(data, alice.private_key)
      # @see #generate_keys
      def generate_signature(bytes, private_key)
        if !bytes.is_a?(Array) || bytes.empty?
          raise ArgumentError.new("bytes is not valid")
        end
        if !private_key.is_a?(VirgilPrivateKey)
          raise ArgumentError.new("private_key is not valid")
        end
        begin
          signer = Native::VirgilSigner.new(HashAlgorithm::SHA512)
          wrap_bytes(signer.sign(bytes, private_key.raw_key))
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end


      # Verifies the specified signature using original data
      # and signer's public key.
      # @param bytes [Crypto::Bytes] original data bytes for verification.
      # @param signature [Crypto::Bytes] signature bytes for verification.
      # @param signer_public_key [VirgilPublicKey] signer public
      # key for verification.
      # @return [Boolean] True if signature is valid, False otherwise.
      # @example Verify the signature of the SHA-384 fingerprint of
      # bytes using Public key.
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   data = Virgil::Crypto::Bytes.from_string('Hello Bob, How are you?')
      #   is_valid = crypto.verify_signature(signature, data, alice.public_key)
      # @see #generate_signature How to get signature
      def verify_signature(signature, bytes, signer_public_key)
        if !bytes.is_a?(Array) || bytes.empty?
          raise ArgumentError.new("bytes is not valid")
        end
        if !signature.is_a?(Array) || signature.empty?
          raise ArgumentError.new("signature is not valid")
        end
        if !signer_public_key.is_a?(VirgilPublicKey)
          raise ArgumentError.new("public_key is not valid")
        end

        begin
          signer = Native::VirgilSigner.new(HashAlgorithm::SHA512)
          signer.verify(bytes, signature, signer_public_key.raw_key)
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end

      end


      # Encrypts the specified stream using public_keys Public keys.
      # @param input_stream [IO] readable stream containing input bytes.
      # @param cipher_stream [IO] writable stream for output.
      # @param *public_keys [Array<VirgilPublicKey>] list of
      # public_keys' public keys.
      # @return [Crypto::Bytes] encrypted bytes.
      # @example
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   File.open('[YOUR_FILE_PATH_HERE]', 'r') do |input_stream|
      #     File.open('[YOUR_CIPHER_FILE_PATH_HERE]', 'w') do |cipher_stream|
      #       crypto.encrypt_stream(input_stream,
      # cipher_stream, alice_keys.public_key)
      #     end
      #   end
      def encrypt_stream(input_stream, cipher_stream, *public_keys)
        if !input_stream.is_a?(IO) || input_stream.empty?
          raise ArgumentError.new("input_stream is not valid")
        end

        if !cipher_stream.is_a?(IO) || cipher_stream.empty?
          raise ArgumentError.new("cipher_stream is not valid")
        end

        begin
          cipher = Crypto::Native::VirgilChunkCipher.new
          public_keys.each do |public_key|
            cipher.add_key_recipient(public_key.id, public_key.raw_key)
          end
          source = Crypto::VirgilStreamDataSource.new(input_stream)
          sink = Crypto::VirgilStreamDataSink.new(cipher_stream)
          cipher.encrypt(source, sink)
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end


      # Decrypts the specified stream using Private key.
      # @param cipher_stream [IO] readable stream containing encrypted data.
      # @param output_stream [IO] writable stream for output.
      # @param private_key [VirgilPrivateKey] private key for decryption.
      # @example
      #   crypto = Virgil::SDK::Cryptography::VirgilCrypto.new
      #   File.open('[YOUR_CIPHER_FILE_PATH_HERE]', 'r') do |cipher_stream|
      #     File.open('[YOUR_DECRYPTED_FILE_PATH_HERE]', 'w') do |decrypted_stream|
      #       alice_private_key = crypto.import_private_key(exported_private_key)
      #       crypto.decrypt_stream(cipher_stream, decrypted_stream, alice_private_key)
      #     end
      #   end
      # @see #encrypt_stream How to get cipher_stream
      # @see #export_private_key How to get exported_private_key
      def decrypt_stream(cipher_stream, output_stream, private_key)
        if !cipher_stream.is_a?(IO) || cipher_stream.empty?
          raise ArgumentError.new("input_stream is not valid")
        end
        if !output_stream.is_a?(IO) || output_stream.empty?
          raise ArgumentError.new("output_stream is not valid")
        end
        if !private_key.is_a?(VirgilPrivateKey)
          raise ArgumentError.new("private_key is not valid")
        end

        begin
          cipher = Crypto::Native::VirgilChunkCipher.new
          source = Crypto::VirgilStreamDataSource.new(cipher_stream)
          sink = Crypto::VirgilStreamDataSink.new(output_stream)
          cipher.decrypt_with_key(
              source,
              sink,
              private_key.id,
              private_key.raw_key
          )
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Signs the specified stream using Private key.
      # @param input_stream [IO] readable stream containing input data.
      # @param private_key [VirgilPrivateKey] private key for signing.
      # @return [Crypto::Bytes] Signature bytes.
      def generate_stream_signature(input_stream, private_key)
        if !input_stream.is_a?(IO) || input_stream.empty?
          raise ArgumentError.new("input_stream is not valid")
        end
        if !private_key.is_a?(VirgilPrivateKey)
          raise ArgumentError.new("private_key is not valid")
        end

        begin
          signer = Native::VirgilStreamSigner.new(HashAlgorithm::SHA512)
          source = VirgilStreamDataSource.new(input_stream)
          wrap_bytes(signer.sign(source, private_key.raw_key))
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end

      # Verifies the specified signature using original stream and signer's Public key.
      # @param input_stream [IO] readable stream containing input data.
      # @param signature [Crypto::Bytes] signature bytes for verification.
      # @param signer_public_key [VirgilPublicKey] signer public key for verification.
      # @return [Boolean] True if signature is valid, False otherwise.
      def verify_stream_signature(signature, input_stream, signer_public_key)
        if !signature.is_a?(Array) || signature.empty?
          raise ArgumentError.new("signature is not valid")
        end
        if !input_stream.is_a?(IO) || input_stream.empty?
          raise ArgumentError.new("input_stream is not valid")
        end
        if !signer_public_key.is_a?(VirgilPublicKey)
          raise ArgumentError.new("public_key is not valid")
        end
        begin
          signer = Crypto::Native::VirgilStreamSigner.new(HashAlgorithm::SHA512)
          source = Crypto::VirgilStreamDataSource.new(input_stream)
          signer.verify(source, signature, signer_public_key.raw_key)
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end


      # Computes the hash of specified data and the specified [HashAlgorithm]
      # @param bytes [Crypto::Bytes] original data bytes to be hashed.
      # @param algorithm [HashAlgorithm] hashing algorithm.
      #   The possible values can be found in HashAlgorithm enum.
      # @return [Crypto::Bytes] Hash bytes.
      def generate_hash(bytes, algorithm = nil)
        if !bytes.is_a?(Array) || bytes.empty?
          raise ArgumentError.new("bytes is not valid")
        end
        alg = algorithm
        alg ||= use_SHA256_fingerprints ? HashAlgorithm::SHA256 : HashAlgorithm::SHA512

        begin
          native_algorithm = HashAlgorithm.convert_to_native(alg)
          native_hasher = Native::VirgilHash.new(native_algorithm)
          wrap_bytes(native_hasher.hash(bytes))
        rescue => error
          raise VirgilCryptoException.new(error.message)
        end
      end


      private

      def wrap_bytes(raw_bytes)
        Crypto::Bytes.new(raw_bytes)
      end

      # Computes the hash of specified public key using SHA256 algorithm.
      # @param public_key [VirgilPublicKey] public key for hashing.
      # @return [Crypto::Bytes] Hash bytes.
      def compute_public_key_hash(public_key)
        public_key_der = Crypto::Native::VirgilKeyPair.public_key_to_der(public_key)
        if use_SHA256_fingerprints
          return generate_hash(public_key_der, HashAlgorithm::SHA256)
        end
        return generate_hash(public_key_der, HashAlgorithm::SHA512)[0..7]
      end
    end
  end
end
