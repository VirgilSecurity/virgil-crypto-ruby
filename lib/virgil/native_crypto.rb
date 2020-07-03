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

require 'virgil/crypto/version'
require 'virgil/os'
require 'net/http'
require 'open-uri'
require 'zlib'
require 'fileutils'
require 'rake'

module NativeCrypto

  LIBRARIES_URL = 'https://cdn.virgilsecurity.com/virgil-crypto/ruby/'.freeze

  def self.download
    file_name = "virgil_crypto_ruby.#{os_ext == 'linux' ? 'so' : 'bundle'}"
    source_url = LIBRARIES_URL + library_path
    puts "Downloading #{source_url}..."
    system('mkdir -p tmp')
    core_path = 'tmp/crypto_core.tar.gz'
    download_archive(source_url, core_path)
    extract_library(core_path, file_name)
  end

  private

  def self.library_path
    list = libraries_list(URI(LIBRARIES_URL))
    ruby_v = "-ruby-#{RUBY_VERSION.sub(/\.[^\.]+$/, '')}-#{os_ext}"
    href_template = /virgil-crypto-#{gem_v}(?:\b-.+\b?)?#{ruby_v}(?!tgz).+tgz"/
    href_list = list.scan href_template
    if href_list.last.nil?
      raise "Sorry. Correct version #{gem_v} of Native Library is missing."
    end
    href_list.last.sub(/"$/, '')
  end

  def self.libraries_list(uri)
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.read_timeout = 100
      request = Net::HTTP::Get.new uri
      response = http.request request
      if response.is_a?(Net::HTTPOK)
        return response.body
      else
        raise "Can't download native library. Please try later."
      end
    end

  end

  def self.gem_v
    # crypto core major version = gem major version - 1
    # crypto core patch version = gem patch version - 1
    Virgil::Crypto::VERSION.scan(/(\d+\.\d+\.\d+)\D*\d*$/) do |postfix|
      core_v = (postfix * '').gsub(/^(\d+)*/) {|gem_maj_ver|  "#{gem_maj_ver.to_i - 1}"}
      return core_v.gsub!(/(\d+)$/) {|gem_patch_ver|  "#{gem_patch_ver.to_i - 1}"}
    end
    ''
  end

  def self.os_ext
    if OS.linux?
      'linux'
    elsif OS.mac?
      'darwin'
    end
  end

  def self.extract_library(archive_path, file_name)
    folder_name = library_path.sub('.tgz', '')
    system("tar xvf #{archive_path} -C tmp/")

    target_file_path = "#{File.expand_path(__dir__)}/crypto/"
    system("cp tmp/#{folder_name}/lib/#{file_name} #{target_file_path}")
  end

  def self.download_archive(source_url, archive_path)
    File.open(archive_path, 'wb') do |file|
      begin
        archive = libraries_list(URI(source_url))
        file.write(archive)
      rescue StandardError => e
        raise "Can't download native library from #{source_url}. Reason: #{e}"
      end
    end
  end
end
