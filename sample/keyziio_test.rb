# A sample client that makes use of the keyziio library
require 'keyziio_client'

class UnAuthenticatedUser < Exception
  # User not logged in
  def to_s
    return 'User is not logged in.'
  end
end

class KzTest
  def initialize
    @logged_in = false
    @username = nil
    @asp_rest_client = KZRestClient.new()
    @asp_rest_client.server_port = 3000
    @asp_rest_client.server_url = 'localhost'
    @keyziio = Keyziio.new()
  end

  def do_login (username)
    # 'login: Logs the user in and sets up the users keyziio session.  Users are created automatically.  Usage: login <username>'
    if is_user_logged_in
      print "Already logged in as #{@username}\n"
      return
    end

    print "logging #{username} in...\n"
    response = @asp_rest_client.get("user_keys/#{username}")

    @keyziio.inject_user_key(JSON.parse(response)['private_key'], JSON.parse(response)['id'])
    @username = username
    @logged_in = true

    print "Successfully retrieved user key and ignited keyziio client\n"
    print "done\n"
  end

  def is_user_logged_in
    return @logged_in
  end

  def do_encrypt (*args)
    #'encrypt: Encrypts input_file with key_id to output_file: Usage: encrypt <input_file> <output_file> <key_id>'
    raise ArgumentError, 'Invalid arguments.  Usage: encrypt <input_file> <output_file> <key_id>' if args.length != 3
    raise UnAuthenticatedUser if not @logged_in
    in_file, out_file, key_id = *args
    print "encrypting #{in_file} with key:#{key_id}...\n"
    @keyziio.encrypt_file(in_file, out_file, key_id)
    print "done\n"
  end

  def do_decrypt (*args)
    # 'decrypt: Decrypts input file to output file.  Gets the key_id from the file header.  Usage: decrypt <input_file> <output_file>'
    raise ArgumentError, 'Invalid arguments.  Usage: decrypt <input_file> <output_file>' if args.length != 2
    raise UnAuthenticatedUser if not @logged_in
    in_file, out_file = *args
    print "decrypting #{in_file}...\n"
    @keyziio.decrypt_file(in_file, out_file)
    print "done\n"
  end
end

if __FILE__ == $0
  shell = KzTest.new()
  shell.do_login('billy')
  shell.do_encrypt('README.md', 'readme.enc', 'ruby_test_key1')
  shell.do_decrypt('readme.enc', 'readme.dec')
end
