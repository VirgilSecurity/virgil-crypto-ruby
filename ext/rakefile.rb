lib = File.expand_path('../../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)


task :default do
  require 'virgil/native_crypto'
  require 'mkmf'

  abort "Sorry, we don't support Ruby with version 2.0! Please Upgrade you Ruby version." if RUBY_VERSION =~ /^2\.0\./
  ROOT_DIR = File.expand_path('../..', __FILE__)
  LIB_DIR = File.join(ROOT_DIR, "lib")
  INSTALL_DIR = File.join(LIB_DIR, 'virgil', 'crypto')

  ext = OS.linux? ? "so" : "bundle"
  begin
    NativeCrypto.load_library
    raise "Native library wasn't loaded" unless File.exists?(File.join(INSTALL_DIR, "virgil_crypto_ruby.#{ext}"))
  rescue

    SCRIPT_DIR = File.expand_path('../', __FILE__)
    SRC_DIR = File.join(SCRIPT_DIR, 'native/src')
    CURRENT_DIR = Dir.pwd
    BUILD_DIR = File.join(ROOT_DIR, "build")
    mkdir_p BUILD_DIR
    cd BUILD_DIR

    CMAKE = find_executable "cmake"
    abort "cmake >= 3.2 is required" unless CMAKE

    check_cmake_version

    INCLUDE_DIRS = [
        RUBY_INCLUDE_DIR = RbConfig::CONFIG['rubyhdrdir'],
        RUBY_CONFIG_INCLUDE_DIR=RbConfig::CONFIG['rubyarchhdrdir']
    ].join(' ').quote
    RUBY_LIB_DIR = RbConfig::CONFIG['libdir']

    CMAKE_COMMAND = [
        CMAKE,
        '-DCMAKE_BUILD_TYPE=Release',
        "-DRUBY_VERSION=#{RUBY_VERSION}",
        "-DRUBY_INCLUDE_DIR=#{RUBY_INCLUDE_DIR}",
        "-DRUBY_CONFIG_INCLUDE_DIR=#{RUBY_CONFIG_INCLUDE_DIR}",
        "-DRUBY_INCLUDE_DIRS=#{INCLUDE_DIRS}",
        "-DRUBY_LIBRARY=#{RUBY_LIB_DIR}",
        '-DCMAKE_SWIG_FLAGS=-autorename',
        "-DCMAKE_INSTALL_PREFIX=#{CURRENT_DIR}",
        "-DINSTALL_API_DIR_NAME=#{INSTALL_DIR}",
        "-DINSTALL_LIB_DIR_NAME=#{INSTALL_DIR}",
        '-DLANG=ruby',
        SRC_DIR
    ].join(' ')

    system(CMAKE_COMMAND)
    system('make -j4')
    system('make install')
    cd '../'
    rm_rf BUILD_DIR
  end
  abort "ERROR! virgil-crypto gem can't be installed because native library wasn't built. Please look at the output above. " unless File.exists?(File.join(INSTALL_DIR, "virgil_crypto_ruby.#{ext}"))

end

def check_cmake_version
  cmake_version_info = `cmake --version`
  if cmake_version_info =~ /(\d+)\.(\d+)\./
    major_version = Regexp.last_match(1).to_i
    minor_version = Regexp.last_match(2).to_i
    abort "cmake >= 3.2 is required" unless (major_version >= 3 && minor_version >= 2)
  else
    abort "Unknown cmake version. cmake >= 3.2 is required"
  end

end





