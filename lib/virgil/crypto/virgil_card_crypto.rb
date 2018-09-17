module Virgil
  module Crypto
    # Provides a cryptographic operations in applications, such as hashing,
    # signature generation and verification, and encryption and decryption.
    class VirgilCardCrypto
      include Virgil::Crypto
      attr_reader virgil_crypto

      # Initializes a new instance of the [VirgilCardCrypto] class.
      def initialize
        @virgil_crypto = VirgilCrypto.new
      end

      # Imports the Public key from material representation.
      # @param key_bytes [Crypto::Bytes] public key material
      # representation bytes.
      # @return [VirgilPublicKey] Imported public key.
      # @example
      #   include Virgil::Crypto
      #   card_crypto = VirgilCardCrypto.new
      #   public_key = card_crypto.import_public_key(exported_public_key)
      # @see #export_public_key How to get exported_public_key
      def import_public_key(key_bytes)
        @virgil_crypto.import_public_key(key_bytes)
      end

      # Exports the Public key into material representation.
      # @param public_key [VirgilPublicKey] public key for export.
      # @return [Crypto::Bytes] Key material representation bytes.
      # @example
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys
      #   card_crypto = VirgilCardCrypto.new
      #   exported_public_key = card_crypto.export_public_key(alice_keys.public_key)
      def export_public_key(public_key)
        @virgil_crypto.export_public_key(public_key)
      end

      # Signs the specified data using Private key.
      # @param bytes [Crypto::Bytes] raw data bytes for signing.
      # @param private_key [VirgilPrivateKey] private key for signing.
      # @return [Crypto::Bytes] Signature data.
      # @example Sign the fingerprint of bytes using your private key.
      #   include Virgil::Crypto
      #   crypto = VirgilCrypto.new
      #   alice_keys = crypto.generate_keys()
      #   # The data to be signed with alice's Private key
      #   data = Bytes.from_string('Hello Bob, How are you?')
      #   card_crypto = VirgilCardCrypto.new
      #   signature = card_crypto.generate_signature(data, alice.private_key)
      def generate_signature(bytes, private_key)
        @virgil_crypto.generate_signature(bytes, private_key)
      end

      # Verifies the specified signature using original data
      # and signer's public key.
      # @param bytes [Crypto::Bytes] original data bytes for verification.
      # @param signature [Crypto::Bytes] signature bytes for verification.
      # @param signer_public_key [VirgilPublicKey] signer public
      # key for verification.
      # @return [Boolean] True if signature is valid, False otherwise.
      # @example Verify the signature of the fingerprint of
      # bytes using Public key.
      #   include Virgil::Crypto
      #   card_crypto = VirgilCardCrypto.new
      #   public_key = crypto.import_public_key(exported_public_key)
      #   data = Bytes.from_string('Hello Bob, How are you?')
      #   is_valid = card_crypto.verify_signature(signature, data, public_key)
      def verify_signature(signature, bytes, signer_public_key)
        @virgil_crypto.verify_signature(signature, bytes, signer_public_key)
      end

      # Calculates the fingerprint.
      # @param bytes [Crypto::Bytes] original data bytes to be hashed.
      # @return [Crypto::Bytes] SHA512 hash value.
      def generate_SHA512(bytes)
        @virgil_crypto.generate_hash(bytes)
      end
    end
  end
end
