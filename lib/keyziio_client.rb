require 'keyziio_client/version.rb'
require 'keyziio_client/kzrestclient.rb'
require 'keyziio_client/kzcrypt.rb'

class UnAuthenticatedUser < Exception
  # User not logged in
  def to_s
    return 'User is not logged in.'
  end
end

class Keyziio
  attr_accessor :username
  def initialize
    @logged_in = false
    @username = nil
    @asp_rest_client = KZRestClient.new()
    @asp_rest_client.server_port = 3000
    @asp_rest_client.server_url = 'localhost'
    @kzcrypt = KZCrypt.new()
  end

  def login_user (username)
    # 'login: Logs the user in and sets up the users keyziio session.  Users are created automatically.
    raise ArgumentError, 'Invalid arguments.  Expecting <username>' if username == nil
    if @logged_in
      return
    end
    response = @asp_rest_client.get("user_keys/#{username}")
    @kzcrypt.inject_user_key(JSON.parse(response)['private_key'], JSON.parse(response)['id'])
    @username = username
    @logged_in = true
  end

  def encrypt_file (in_file, out_file, key_id)
    #'encrypt: Encrypts input_file with key_id to output_file.'
    raise UnAuthenticatedUser if not @logged_in
    @kzcrypt.encrypt_file(in_file, out_file, key_id)
  end

  def decrypt_file (in_file, out_file)
    # 'decrypt: Decrypts input file to output file.  Gets the key_id from the file header.'
    raise UnAuthenticatedUser if not @logged_in
    @kzcrypt.decrypt_file(in_file, out_file)
  end

  def is_user_logged_in
    return @logged_in
  end
end

if __FILE__ == $0
  shell = Keyziio.new()
  shell.login_user('billy')
  shell.encrypt_file('README.md', 'readme_rb.enc', 'ruby_test_key1')
  #shell.decrypt_file('readme_rb.enc', 'readme.dec')
end
