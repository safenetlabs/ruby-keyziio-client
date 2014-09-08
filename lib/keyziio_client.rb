require 'keyziio_client/version.rb'
require 'keyziio_client/kzrestclient.rb'
require 'keyziio_client/kzcrypt.rb'

require 'json'
require 'base64'

class KZClient

  def initialize (keychain_id, token_hash, user_key = nil, server_url='https://keyziio2.herokuapp.com')
    @kzrestclient = KZRestClient.new(keychain_id, token_hash, server_url)
    @kzcrypt = KZCrypt.new(@kzrestclient, user_key)
    @session_rsa_key = nil
  end

  def get_session_key
    # Generate session key pair and return public
    @session_rsa_key = @kzcrypt.create_key_pair 2048

    # return public key
    return @session_rsa_key.public_key.to_pem
  end

  def construct_user_key (wrapped_user_key_pt1)
    user_key_pt1 = @kzcrypt.unwrap_key(Base64.decode64(wrapped_user_key_pt1), @session_rsa_key)

    # Request user key pt2 from keyziio server
    response = @kzrestclient.get_user_key(@session_rsa_key.public_key.to_pem)

    # parse response for wrapped user_key_pt2
    wrapped_user_key_pt2 = JSON.parse(response)['bytes']

    # unwrap user_key_pt2 with session private
    user_key_pt2 = @kzcrypt.unwrap_key(Base64.decode64(wrapped_user_key_pt2), @session_rsa_key)

    # Combine (xor) user key parts and construct user key
    #@kzcrypt.construct_user_key(Base64.decode64(user_key_pt1), Base64.decode64(user_key_pt2))
    @kzcrypt.construct_user_key(user_key_pt1, user_key_pt2)
  end

  def encrypt_file (in_file, out_file, key_name)
    #'encrypt: Encrypts input_file with key_name to output_file.'
    @kzcrypt.encrypt_file(in_file, out_file, key_name)
  end

  def decrypt_file (in_file, out_file)
    # 'decrypt: Decrypts input file to output file.  Gets the key_id from the file header.'
    @kzcrypt.decrypt_file(in_file, out_file)
  end

  def encrypt_buffer (buf_in, key_name)
    # Encrypts buf_in using key_name.  It will create the key if it has to.
    @kzcrypt.encrypt_buffer(buf_in, key_name)
  end

  def decrypt_buffer (buf_in)
    # Decrypts buf_in using key_id.  It will create the key if it has to.
    @kzcrypt.decrypt_buffer(buf_in)
  end
end

