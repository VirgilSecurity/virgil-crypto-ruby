require "bundler/gem_tasks"
require 'rake/extensiontask'
require 'rake/testtask'
require 'mkmf'

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = FileList['test/**/*_test.rb']
end

task :default => :test


namespace :native_sources do

  task :download do
    system('git submodule init')
    system('git submodule update --recursive')
  end


  task :run_cmake => :download do
    mkdir_p 'build'
    cd 'build'

    CMAKE = find_executable "cmake"
    abort "cmake >= 3.2 is required" unless CMAKE

    SCRIPT_DIR = File.expand_path('../', __FILE__)
    SRC_DIR = File.join(SCRIPT_DIR, 'ext/native/src')
    CURRENT_DIR = Dir.pwd
    LIB_DIR = File.join(SCRIPT_DIR, "lib")
    INSTALL_DIR = File.join(LIB_DIR, 'virgil', 'crypto')
    INCLUDE_DIRS = [
        RUBY_INCLUDE_DIR = RbConfig::CONFIG['rubyhdrdir'],
        RUBY_CONFIG_INCLUDE_DIR=RbConfig::CONFIG['rubyarchhdrdir']
    ].join(' ').quote
    RUBY_LIB_DIR = RbConfig::CONFIG['libdir']


    # CMAKE_COMMAND = [
    #     CMAKE,
    #     '-DCMAKE_BUILD_TYPE=Release',
    #     "-DCMAKE_INSTALL_PREFIX=#{CURRENT_DIR}",
    #     "-DINSTALL_API_DIR_NAME=#{INSTALL_DIR}",
    #     "-DINSTALL_LIB_DIR_NAME=#{INSTALL_DIR}",
    #     '-DLANG=ruby',
    #     SRC_DIR
    # ].join(' ')

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
    rm_rf 'build'

  end

end

