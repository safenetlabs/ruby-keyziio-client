require 'keyziio_client/version.rb'
require 'keyziio_client/kzrestclient.rb'
require 'keyziio_client/kzcrypt.rb'

require 'json'

class KZClient

  def initialize (client_id, client_secret, keychain_id)
    @kzrestclient = KZRestClient.new(client_id, client_secret, keychain_id)
    @kzcrypt = KZCrypt.new(@kzrestclient)
    @keychain_id = nil
    @session_rsa_key = nil

    # Ignite the client
    @keychain_id = keychain_id

    # Generate session key pair and return public
    @session_rsa_key = @kzcrypt.create_key_pair 2048
    # return public key
    @session_rsa_key.public_key.to_pem
  end

  def inject_user_key (wrapped_user_key_pt1)
    user_key_pt1 = @kzcrypt.unwrap_key(wrapped_user_key_pt1, @session_rsa_key.private_key)

    # Request user key pt2 from keyziio server
    response = @kzrestclient.get_user_key(@session_rsa_key.public_key.to_pem)

    # parse response for wrapped user_key_pt2
    wrapped_user_key_pt2 = JSON.parse(response)['bytes']

    # unwrap user_key_pt2 with session private
    user_key_pt2 = @kzcrypt.unwrap_key(wrapped_user_key_pt2, @session_rsa_key.private_key)

    # Combine (xor) user key parts and construct user key
    @kzcrypt.inject_user_key(user_key_pt1, user_key_pt2)
  end

  def encrypt_file (in_file, out_file, key_id)
    #'encrypt: Encrypts input_file with key_id to output_file.'
    @kzcrypt.encrypt_file(in_file, out_file, key_id)
  end

  def decrypt_file (in_file, out_file)
    # 'decrypt: Decrypts input file to output file.  Gets the key_id from the file header.'
    @kzcrypt.decrypt_file(in_file, out_file)
  end

  def encrypt_buffer (buf_in, key_id)
    # Encrypts buf_in using key_id.  It will create the key if it has to.
    @kzcrypt.encrypt_buffer(buf_in, key_id)
  end

  def decrypt_buffer (buf_in)
    # Decrypts buf_in using key_id.  It will create the key if it has to.
    @kzcrypt.decrypt_buffer(buf_in)
  end
end

