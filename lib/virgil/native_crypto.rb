require 'virgil/crypto/version'
require 'virgil/os'
require 'net/http'
require 'open-uri'
require 'zlib'
require 'fileutils'
require 'rake'

module NativeCrypto
  module_function

  LIBRARIES_URL = 'https://cdn.virgilsecurity.com/virgil-crypto/ruby/'.freeze

  def load_library
    file_name = "virgil_crypto_ruby.#{os_ext == 'linux' ? 'so' : 'bundle'}"
    download_library(library_url, file_name)
  end

  def library_url
    list = libraries_list(URI(LIBRARIES_URL))
    ruby_v = "-ruby-#{RUBY_VERSION.sub(/\.[^\.]+$/, '')}-#{os_ext}"
    href_template = /virgil-crypto-#{gem_v}(?:\b-.+\b?)?#{ruby_v}(?!tgz).+tgz"/
    href_list = list.scan href_template
    if href_list.last.nil?
      raise "Sorry. Correct version #{gem_v} of Native Library is missing."
    end
    href_list.last.sub(/"$/, '')
  end

  def libraries_list(uri)
    Net::HTTP.start(uri.host, uri.port, use_ssl: true) do |http|
      http.read_timeout = 100
      request = Net::HTTP::Get.new uri
      response = http.request request
      if response == Net::HTTPSuccess
        response.body
      else
        raise "Can't download native library. Please try later."
      end
    end
  end

  def gem_v
    Virgil::Crypto::VERSION.scan(/(\d+\.\d+\.\d+)\D*\d*$/) do |postfix|
      return postfix * ''
    end
    return ''
  end

  def self.os_ext
    if OS.linux?
      'linux'
    elsif OS.mac?
      'darwin'
    end
  end

  def download_library(source_path, file_name)
    puts "Downloading #{source_path}..."
    system('mkdir -p tmp')
    archive_path = 'tmp/native_library.tar.gz'
    File.new(archive_path, 'w') do |local_file|
      begin
        open(LIBRARIES_URL + source_path) do |remote_file|
          local_file.write(Zlib::GzipReader.new(remote_file).read)
        end
      rescue Exception => e
        raise "Can't download native library from #{source_path} by reason: #{e}"
      end
    end

    library_folder_name = source_path.sub('.tgz', '')

    system("tar xvf #{archive_path} -C tmp/")

    target_file_path = "#{File.expand_path(__dir__)}/crypto/#{file_name}"
    system("cp tmp/#{library_folder_name}/lib/#{file_name} #{target_file_path}")
    system('rm -rf tmp')

  end

end
