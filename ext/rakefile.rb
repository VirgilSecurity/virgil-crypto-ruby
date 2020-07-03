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

LIB_DIR = File.expand_path('../lib', __dir__)
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
  core_install_dir = File.join(EXT_DIR, 'native', 'src', 'install', 'ruby')
  build_dir = File.join(EXT_DIR, 'native', 'src', 'build')

  Thread.new {
    system 'cd native/src; ./utils/build.sh --target=ruby; cd ../.. '
  }.join
  system "ls #{core_install_dir}"
  if Dir.empty?(core_install_dir)
    abort "ERROR! virgil-crypto gem can't be installed because native "\
"library wasn't built. Please look at the output above."
  end
  system "cp #{build_dir}/ruby/wrappers/ruby/#{core_filename} #{File.join(INSTALL_DIR, core_filename)}"

  system "rm -rf #{build_dir} && rm -rf #{core_install_dir}"
end





