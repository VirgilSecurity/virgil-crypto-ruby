require "virgil/crypto/version"
module Virgil
  module Crypto
    autoload :Virgil_crypto_ruby, 'virgil/crypto/virgil_crypto_ruby'
    autoload :Bytes, 'virgil/crypto/bytes'
    autoload :VirgilStreamDataSink, 'virgil/crypto/virgil_stream_data_sink'
    autoload :VirgilStreamDataSource, 'virgil/crypto/virgil_stream_data_source'
    Native = Virgil_crypto_ruby
  end
end
