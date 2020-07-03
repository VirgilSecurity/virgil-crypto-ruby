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
    # Wrapper for cryptographic operations.
    #
    # Class provides a cryptographic operations in applications, such as
    # hashing, signature generation and verification, key creation,
    # import and export key, encryption and decryption.
    class VirgilCrypto
      attr_reader :default_key_type
      attr_accessor :use_SHA256_fingerprints

      def initialize(key_pair_type: KeyPairType::Default)
        @default_key_type = key_pair_type
      end

      CUSTOM_PARAM_KEY_SIGNATURE = Bytes.from_string(
        'VIRGIL-DATA-SIGNATURE'
      )

      CUSTOM_PARAM_KEY_SIGNER_ID = Bytes.from_string(
        'VIRGIL-DATA-SIGNER-ID'
      )

      # Generates asymmetric key pair that is comprised of both public
      # and private keys by specified type.
      # @param keys_type [Symbol] type of the generated keys.
      #   The possible values can be found in KeyPairType enum.
      # @param key_material [Bytes] the only data to be used for
      # key generation, length must be more than 31.
      # @return [KeyPair] Generated key pair with the special type.
      # @example Generated key pair with default type FAST_EC_ED25519
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      # @example Generated key pair with type EC_SECP256R1
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys(key_type: KeyPairType::EC_SECP256R1)
      def generate_keys(keys_type: @default_key_type, key_material: nil)
        key_material = Validation.check_filled_array_argument!(key_material) if key_material
        begin
          native_type = KeyPairType.convert_to_native(keys_type)
          native_key_pair = nil
          native_key_pair = if key_material
                              Core::VirgilKeyPair.generate_from_key_material(
                                native_type,
                                key_material
                              )
                            else
                              Core::VirgilKeyPair.generate(native_type)
                            end
          key_pair_id = compute_public_key_hash(native_key_pair.public_key)
          private_key = VirgilPrivateKey.new(
            key_pair_id,
            wrap_bytes(
              Core::VirgilKeyPair.private_key_to_der(native_key_pair.private_key)
            )
          )
          public_key = VirgilPublicKey.new(
            key_pair_id,
            wrap_bytes(
              Core::VirgilKeyPair.public_key_to_der(native_key_pair.public_key)
            )
          )
          return KeyPair.new(private_key, public_key)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Imports the Private key from material representation.
      # @param key_bytes [Bytes] private key material
      # representation bytes.
      # @param password [String] private key password, nil by default.
      # @return [VirgilPrivateKey] Imported private key.
      # @example
      #   private_key = crypto.import_private_key(exported_private_key, 'my_password')
      # @see #export_private_key How to get exported_private_key
      def import_private_key(key_bytes, password = nil)
        key_bytes = Validation.check_filled_array_argument!(key_bytes)

        begin
          decrypted_private_key = if !password
                                    Core::VirgilKeyPair.private_key_to_der(key_bytes)
                                  else
                                    Core::VirgilKeyPair.decrypt_private_key(
                                        key_bytes,
                                        Bytes.from_string(password)
                                    )
                                  end

          public_key_bytes = Core::VirgilKeyPair.extract_public_key(
              decrypted_private_key, []
          )
          key_pair_id = compute_public_key_hash(public_key_bytes)
          private_key_bytes = Core::VirgilKeyPair.private_key_to_der(
              decrypted_private_key
          )
          return VirgilPrivateKey.new(key_pair_id, wrap_bytes(private_key_bytes))
        rescue => error
          raise VirgilCryptoException, error.message
        end

      end

      # Imports the Public key from material representation.
      # @param key_bytes [Bytes] public key material
      # representation bytes.
      # @return [VirgilPublicKey] Imported public key.
      # @example
      #   public_key = crypto.import_public_key(exported_public_key)
      # @see #export_public_key How to get exported_public_key
      def import_public_key(key_bytes)
        key_bytes = Validation.check_filled_array_argument!(key_bytes)

        begin
          key_pair_id = compute_public_key_hash(key_bytes)
          public_key_bytes = Core::VirgilKeyPair.public_key_to_der(key_bytes)
          VirgilPublicKey.new(key_pair_id, wrap_bytes(public_key_bytes))
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Exports the Private key into material representation.
      # @param private_key [VirgilPrivateKey] private key for export.
      # @param password [String] private key password, nil by default.
      # @return [Bytes] Private key material representation bytes.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      #   exported_private_key = crypto.export_private_key(alice_keys.private_key, 'my_password')
      def export_private_key(private_key, password = nil)
        private_key = Validation.check_type_argument!(VirgilPrivateKey, private_key)

        begin
          unless password
            return Core::VirgilKeyPair.private_key_to_der(
              private_key.raw_key
            )
          end
          password_bytes = Bytes.from_string(password)
          private_key_bytes = Core::VirgilKeyPair.encrypt_private_key(
            private_key.raw_key,
            password_bytes
          )
          wrap_bytes(
            Core::VirgilKeyPair.private_key_to_der(
              private_key_bytes,
              password_bytes
            )
          )
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Exports the Public key into material representation.
      # @param public_key [VirgilPublicKey] public key for export.
      # @return [Bytes] Key material representation bytes.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      #   exported_public_key = crypto.export_public_key(alice_keys.public_key)
      def export_public_key(public_key)
        public_key = Validation.check_type_argument!(VirgilPublicKey, public_key)

        begin
          wrap_bytes(
            Core::VirgilKeyPair.public_key_to_der(public_key.raw_key)
          )
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Extracts the Public key from Private key.
      # @param private_key [VirgilPrivateKey] source private
      # key for extraction.
      # @return [VirgilPublicKey] Exported public key.
      def extract_public_key(private_key)
        private_key = Validation.check_type_argument!(VirgilPrivateKey, private_key)

        begin
          public_key_bytes = Core::VirgilKeyPair.extract_public_key(
            private_key.raw_key,
            []
          )
          VirgilPublicKey.new(
            private_key.id,
            wrap_bytes(
              Core::VirgilKeyPair.public_key_to_der(public_key_bytes)
            )
          )
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Encrypts the specified data using the specified recipients Public keys.
      # @param bytes [Virgil::Bytes] raw data bytes for encryption.
      # @param *public_keys [Array<VirgilPublicKey>] list
      # of public keys.
      # @return [Bytes] Encrypted bytes.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      #   plain_data = Bytes.from_string('Hello Bob!')
      #   cipher_data = crypto.encrypt(plain_data, alice_keys.public_key)
      # @see #generate_keys How to generate keys
      # @see #decrypt How to decrypt data
      def encrypt(bytes, *public_keys)
        bytes = Validation.check_filled_array_argument!(bytes)

        begin
          encrypt_for_recipients(bytes, Core::VirgilCipher.new, public_keys)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Decrypts the specified bytes using Private key.
      # @param cipher_bytes [Bytes] encrypted data bytes for decryption.
      # @param private_key [VirgilPrivateKey] private key for decryption.
      # @return [Bytes] Decrypted data bytes.
      # @example
      #   # You can decrypt data using your private key
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      #   plain_data = crypto.decrypt(cipher_data, alice_keys.private_key)
      # @see #generate_keys
      # @see #encrypt How to get cipher_data
      def decrypt(cipher_bytes, private_key)
        cipher_bytes = Validation.check_filled_array_argument!(cipher_bytes)
        private_key = Validation.check_type_argument!(VirgilPrivateKey, private_key)

        begin
          cipher = Core::VirgilCipher.new
          decrypted_bytes = cipher.decrypt_with_key(
            cipher_bytes,
            private_key.id,
            private_key.raw_key
          )
          wrap_bytes(decrypted_bytes)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Signs and encrypts the data.
      # @param bytes [Bytes] data bytes for signing and encryption.
      # @param private_key [VirgilPrivateKey] private key to sign the data.
      # @param *public_keys [Array<VirgilPublicKey>] list of public keys
      #  to encrypt the data.
      # @return [Bytes] Signed and encrypted data bytes.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #
      #   alice = crypto.generate_keys
      #   bob = crypto.generate_keys
      #
      #   # The data to be signed with alice's Private key
      #   data = Bytes.from_string('Hello Bob, How are you?')
      #   cipher_data = crypto.sign_then_encrypt(
      #     data,
      #     alice.private_key,
      #     bob.public_key
      #   )
      def sign_then_encrypt(bytes, private_key, *public_keys)
        bytes = Validation.check_filled_array_argument!(bytes)
        private_key = Validation.check_type_argument!(VirgilPrivateKey, private_key)

        begin
          cipher = Core::VirgilCipher.new
          custom_bytes = cipher.custom_params
          custom_bytes.set_data(
            CUSTOM_PARAM_KEY_SIGNATURE,
            generate_signature(bytes, private_key)
          )

          public_key = extract_public_key(private_key)
          custom_bytes.set_data(
            CUSTOM_PARAM_KEY_SIGNER_ID,
            wrap_bytes(public_key.id)
          )
          encrypt_for_recipients(bytes, cipher, public_keys)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Decrypts and verifies the data.
      # @param bytes [Bytes] encrypted data bytes.
      # @param private_key [VirgilPrivateKey] private key for decryption.
      # @param *public_keys [Array<VirgilPublicKey>] a list of public keys
      # for verification,
      #   which can contain signer's public key.
      # @return [Bytes] Decrypted data bytes.
      # @raise [VirgilCryptoException] if signature is not verified.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
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
        bytes = Validation.check_filled_array_argument!(bytes)
        private_key = Validation.check_type_argument!(VirgilPrivateKey, private_key)

        begin
          cipher = Core::VirgilCipher.new
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

          is_valid = verify_signature(signature, decrypted_bytes, signer_public_key)
          raise VirgilCryptoException, 'Signature is not valid' unless is_valid

          wrap_bytes(decrypted_bytes)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Signs the specified data using Private key.
      # @param bytes [Bytes] raw data bytes for signing.
      # @param private_key [VirgilPrivateKey] private key for signing.
      # @return [Bytes] Signature data.
      # @example Sign the fingerprint of bytes using your private key.
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   # The data to be signed with alice's Private key
      #   data = Bytes.from_string('Hello Bob, How are you?')
      #   signature = crypto.generate_signature(data, alice.private_key)
      # @see #generate_keys
      # @see #verify_signature How to verify signature
      def generate_signature(bytes, private_key)
        bytes = Validation.check_filled_array_argument!(bytes)
        private_key = Validation.check_type_argument!(VirgilPrivateKey, private_key)

        begin
          native_algorithm = HashAlgorithm.convert_to_native(HashAlgorithm::SHA512)
          signer = Core::VirgilSigner.new(native_algorithm)
          wrap_bytes(signer.sign(bytes, private_key.raw_key))
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Verifies the specified signature using original data
      # and signer's public key.
      # @param bytes [Bytes] original data bytes for verification.
      # @param signature [Bytes] signature bytes for verification.
      # @param signer_public_key [VirgilPublicKey] signer public
      # key for verification.
      # @return [Boolean] True if signature is valid, False otherwise.
      # @example Verify the signature of the fingerprint of
      # bytes using Public key.
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   data = Bytes.from_string('Hello Bob, How are you?')
      #   is_valid = crypto.verify_signature(signature, data, alice.public_key)
      # @see #generate_signature How to get signature
      def verify_signature(signature, bytes, signer_public_key)
        signature = Validation.check_filled_array_argument!(signature)
        bytes = Validation.check_filled_array_argument!(bytes)
        signer_public_key = Validation.check_type_argument!(VirgilPublicKey, signer_public_key)

        begin
          native_algorithm = HashAlgorithm.convert_to_native(HashAlgorithm::SHA512)
          signer = Core::VirgilSigner.new(native_algorithm)
          signer.verify(bytes, signature, signer_public_key.raw_key)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end

      end

      # Encrypts the specified stream using public_keys Public keys.
      # @param input_stream [IO] readable stream containing input bytes.
      # @param cipher_stream [IO] writable stream for output.
      # @param *public_keys [Array<VirgilPublicKey>] list of
      # public_keys' public keys.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   File.open('[YOUR_FILE_PATH_HERE]', 'r') do |input_stream|
      #     File.open('[YOUR_CIPHER_FILE_PATH_HERE]', 'w') do |cipher_stream|
      #       crypto.encrypt_stream(input_stream,
      # cipher_stream, alice_keys.public_key)
      #     end
      #   end
      def encrypt_stream(input_stream, cipher_stream, *public_keys)
        begin
          cipher = Core::VirgilChunkCipher.new
          public_keys.each do |public_key|
            public_key = Validation.check_type_argument!(VirgilPublicKey, public_key)
            cipher.add_key_recipient(public_key.id, public_key.raw_key)
          end
          source = VirgilStreamDataSource.new(input_stream)
          sink = VirgilStreamDataSink.new(cipher_stream)
          cipher.encrypt(source, sink)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Decrypts the specified stream using Private key.
      # @param cipher_stream [IO] readable stream containing encrypted data.
      # @param output_stream [IO] writable stream for output.
      # @param private_key [VirgilPrivateKey] private key for decryption.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   File.open('[YOUR_CIPHER_FILE_PATH_HERE]', 'r') do |cipher_stream|
      #     File.open('[YOUR_DECRYPTED_FILE_PATH_HERE]', 'w') do |decrypted_stream|
      #       alice_private_key = crypto.import_private_key(exported_private_key)
      #       crypto.decrypt_stream(cipher_stream, decrypted_stream, alice_private_key)
      #     end
      #   end
      # @see #encrypt_stream How to get cipher_stream
      # @see #export_private_key How to get exported_private_key
      def decrypt_stream(cipher_stream, output_stream, private_key)
        private_key = Validation.check_type_argument!(VirgilPrivateKey, private_key)
        begin
          cipher = Core::VirgilChunkCipher.new
          source = VirgilStreamDataSource.new(cipher_stream)
          sink = VirgilStreamDataSink.new(output_stream)
          cipher.decrypt_with_key(source, sink, private_key.id, private_key.raw_key)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Signs the specified stream using Private key.
      # @param input_stream [IO] readable stream containing input data.
      # @param private_key [VirgilPrivateKey] private key for signing.
      # @return [Bytes] Signature bytes.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   File.open('[YOUR_FILE_PATH_HERE]', 'r') do |input_stream|
      #       signature = crypto.generate_stream_signature(input_stream, alice_keys.private_key)
      #   end
      #  @see #verify_stream_signature How to verify the signature
      def generate_stream_signature(input_stream, private_key)
        private_key = Validation.check_type_argument!(VirgilPrivateKey, private_key)

        begin
          native_algorithm = HashAlgorithm.convert_to_native(HashAlgorithm::SHA512)
          signer = Core::VirgilStreamSigner.new(native_algorithm)
          source = VirgilStreamDataSource.new(input_stream)
          wrap_bytes(signer.sign(source, private_key.raw_key))
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Verifies the specified signature using original stream and signer's Public key.
      # @param input_stream [IO] readable stream containing input data.
      # @param signature [Bytes] signature bytes for verification.
      # @param signer_public_key [VirgilPublicKey] signer public key for verification.
      # @return [Boolean] True if signature is valid, False otherwise.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   File.open('[YOUR_FILE_PATH_HERE]', 'r') do |input_stream|
      #       verified = crypto.verify_stream_signature(signature, input_stream, alice_keys.public_key)
      #   end
      #  @see #generate_stream_signature How to get the signature
      def verify_stream_signature(signature, input_stream, signer_public_key)
        signature = Validation.check_filled_array_argument!(signature)
        signer_public_key = Validation.check_type_argument!(VirgilPublicKey, signer_public_key)

        begin
          native_algorithm = HashAlgorithm.convert_to_native(HashAlgorithm::SHA512)
          signer = Core::VirgilStreamSigner.new(native_algorithm)
          source = VirgilStreamDataSource.new(input_stream)
          signer.verify(source, signature, signer_public_key.raw_key)
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      # Computes the hash of specified data and the specified [HashAlgorithm]
      # @param bytes [Bytes] original data bytes to be hashed.
      # @param algorithm [HashAlgorithm] hashing algorithm.
      #   The possible values can be found in HashAlgorithm enum.
      # @return [Bytes] Hash bytes.
      def generate_hash(bytes, algorithm = nil)
        bytes = Validation.check_filled_array_argument!(bytes)

        alg = algorithm
        alg ||= use_SHA256_fingerprints ? HashAlgorithm::SHA256 : HashAlgorithm::SHA512

        begin
          native_algorithm = HashAlgorithm.convert_to_native(alg)
          native_hasher = Core::VirgilHash.new(native_algorithm)
          wrap_bytes(native_hasher.hash(bytes))
        rescue StandardError => error
          raise VirgilCryptoException, error.message
        end
      end

      private

      attr_reader :default_key_type

      def encrypt_for_recipients(bytes, cipher, public_keys)
        public_keys.each do |public_key|
          public_key = Validation.check_type_argument!(VirgilPublicKey, public_key)
          cipher.add_key_recipient(public_key.id, public_key.raw_key)
        end
        wrap_bytes(cipher.encrypt(bytes, true))
      end

      def wrap_bytes(raw_bytes)
        Bytes.new(raw_bytes)
      end

      # Computes the hash of specified public key using SHA256 algorithm.
      # @param public_key [VirgilPublicKey] public key for hashing.
      # @return [Bytes] Hash bytes.
      def compute_public_key_hash(public_key)
        public_key_der = Core::VirgilKeyPair.public_key_to_der(public_key)
        if use_SHA256_fingerprints
          return generate_hash(public_key_der, HashAlgorithm::SHA256)
        end

        generate_hash(public_key_der, HashAlgorithm::SHA512)[0..7]
      end
    end
  end
end
