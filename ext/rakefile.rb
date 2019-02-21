LIB_DIR = File.expand_path('lib', __dir__)
EXT_DIR = File.expand_path(__dir__)
INSTALL_DIR = File.join(LIB_DIR, 'virgil', 'crypto')
$LOAD_PATH.unshift(LIB_DIR) unless $LOAD_PATH.include?(LIB_DIR)

task :default do
  require 'virgil/native_crypto'
  require 'mkmf'

  if RUBY_VERSION =~ /^2\.0\./
    abort "We don't support Ruby version <=2.1.10! Please Upgrade your Ruby."
  end

  abort "Sorry, we don't support Windows platform yet." if OS.windows?

  core_filename = "virgil_crypto_ruby.#{OS.linux? ? 'so' : 'bundle'}"
  begin
    NativeCrypto.download
    unless File.exists?(File.join(INSTALL_DIR, core_filename))
      raise "Native library wasn't loaded."
    end
  rescue StandardError
    puts 'Building Native library...'

    check_cmake
    build_native_crypto(core_filename)
  end

end

def check_cmake
  cmake_cmd = find_executable 'cmake'
  abort 'cmake >= 3.10 is required' unless cmake_cmd
  cmake_version_info = `cmake --version`
  if cmake_version_info =~ /(\d+)\.(\d+)\./
    major_version = Regexp.last_match(1).to_i
    minor_version = Regexp.last_match(2).to_i
    unless major_version >= 3 && minor_version >= 10
      abort 'cmake >= 3.10 is required'
    end
  else
    abort 'Unknown cmake version. cmake >= 3.10 is required'
  end

end

def build_native_crypto(core_filename)
  core_install_dir = File.join(EXT_DIR, 'native',
                               'src', 'install', 'ruby')
  Thread.new { system './utils/build.sh --target=ruby' }.join
  system "ls #{core_install_dir}"
  if Dir.empty?(core_install_dir)
    abort "ERROR! virgil-crypto gem can't be installed because native "\
"library wasn't built. Please look at the output above."
  end
  system "cp #{core_install_dir}/*.tgz #{File.join(INSTALL_DIR, core_filename)}"
  system 'rm -rf build && rm -rf install'
end





