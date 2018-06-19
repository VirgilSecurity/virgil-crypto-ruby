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
    archive_path = 'tmp/native_library.tar.gz'
    download_archive(source_url, archive_path)
    extract_library(archive_path, file_name)
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
      if response == Net::HTTPSuccess
        response.body
      else
        raise "Can't download native library. Please try later."
      end
    end
  end

  def self.gem_v
    Virgil::Crypto::VERSION.scan(/(\d+\.\d+\.\d+)\D*\d*$/) do |postfix|
      return postfix * ''
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
    target_file_path = "#{File.expand_path(__dir__)}/crypto/#{file_name}"
    system("cp tmp/#{folder_name}/lib/#{file_name} #{target_file_path}")
    system('rm -rf tmp')
  end

  def self.download_archive(source_url, archive_path)
    File.new(archive_path, 'w') do |file|
      begin
        uri = URI.parse(source_url)
        uri.open { |source| file.write(GzipReader.new(source).read) }
      rescue StandardError => e
        raise "Can't download native library from #{source_url}. Reason: #{e}"
      end
    end
  end
end
