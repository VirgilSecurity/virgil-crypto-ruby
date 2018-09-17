module Virgil
  module Crypto
    # Provides a cryptographic operations in applications, such as signature generation
    # and verification in an access token.
    class VirgilAccessTokenSigner
      attr_reader virgil_crypto

      # Represents used signature algorithm.
      attr_reader algorithm
      private :virgil_crypto

      # Initializes a new instance of the [VirgilAccessTokenSigner] class.
      def initialize
        @virgil_crypto = VirgilCrypto.new
        @algorithm = 'VEDS512'
      end

      # Generates the digital signature for the specified token_bytes
      #  using the specified [VirgilPrivateKey]
      # @param token_bytes [Crypto::Bytes] The material representation bytes of access token
      # for which to compute the signature.
      # @param private_key [VirgilPrivateKey] The digital signature for the material representation
      # bytes of access token.
      # @return The digital signature for the material representation bytes of access token.
      def generate_token_signature(token_bytes, private_key)
        @virgil_crypto.generate_signature(token_bytes, private_key)
      end

      # Verifies that a digital signature is valid by checking the signature,
      # provided public_key and token_bytes
      # @param signature [Crypto::Bytes] The digital signature for the token_bytes
      # @param token_bytes [Crypto::Bytes] The material representation bytes of access token
      # for which the signature has been generated.
      # @param public_key [VirgilPublicKey] public
      # key for verification.
      # @return [Boolean] True if signature is valid, False otherwise.
      def verify_token_signature(signature, token_bytes, public_key)
        @virgil_crypto.verify_signature(signature, token_bytes, public_key)
      end
    end
  end
end