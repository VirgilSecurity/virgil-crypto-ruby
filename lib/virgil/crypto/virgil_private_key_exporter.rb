module Virgil
  module Crypto
    # Provides export [PrivateKey] into its material representation bytes and
    # import [PrivateKey] from its material representation bytes.
    class VirgilPrivateKeyExporter
      include Virgil::Crypto
      attr_reader virgil_crypto
      attr_reader password

      # Initializes a new instance of the [VirgilPrivateKeyExporter] class.
      # @param password [String] private key password, nil by default.
      def initialize(password = nil)
        @password = password
        @virgil_crypto = VirgilCrypto.new
      end

      # Initializes a new instance of the [VirgilPrivateKeyExporter] class.
      # @param password [String] private key password, nil by default.
      # @param crypto the instance of [Crypto::VirgilCrypto]
      # that is used for export and import of [PrivateKey]
      def initialize(crypto, password = nil)
        @password = password
        @virgil_crypto = crypto
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