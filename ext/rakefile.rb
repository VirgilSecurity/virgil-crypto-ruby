 lib = File.expand_path('../../lib', __FILE__)
 $LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

task :default do
  require 'virgil/native_crypto'

  NativeCrypto.load_library

end

