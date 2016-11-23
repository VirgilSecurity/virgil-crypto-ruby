require "virgil/crypto/version"

module Virgil
  module Crypto
    autoload :Native, 'virgil/crypto/native'
    autoload :Bytes, 'virgil/crypto/bytes'
    autoload :VirgilStreamDataSink, 'virgil/crypto/virgil_stream_data_sink'
    autoload :VirgilStreamDataSource, 'virgil/crypto/virgil_stream_data_source'
  end
end
