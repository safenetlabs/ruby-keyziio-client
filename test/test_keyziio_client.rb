require 'test/unit'
require 'keyziio_client'
require 'json'
require 'base64'
require 'keyziio_client/kzrestclient'
require 'keyziio_client/kzcrypt'
require 'securerandom'
require 'fileutils'

class TestKeyziioClient < Test::Unit::TestCase
    @@keychain_id = '14215f9b-aacb-42bf-9378-88f5657724e9'
    @@access_token = '6cd0150b2d5f7ba7ebe50ddbb5250c4b6e50a505a83fb6814a65fda16f23a4ff'
    @@server_url = 'https://keyziio2.herokuapp.com'
    @@keychain_key = 'zkDfxiANZ1BN8jV4Sy6pWLX0VLtTkR6IEpd7QkFg0zo='
    @@test_buffer = 'This is a test'
    @@encrypted_buffer = 'www.keyziio.com Encrypted File                                                                                                  d371004cba8d4fafaeb324f72a52d91b   z   {"key_id":"986c3463-3b28-4fb0-bda1-c95057e1820f","mac":"60d715564ea2c5b35af4aac717b4943db7cd09eb4e08c4bddd6848961fb87cf8"}bl9MxMEStlJkocDB4/y5Fw=='
    @@blocksize_buffer = 'This is a tester'
    @@test_file_in = './test_file_in'
    @@test_file_enc = './test_file_enc'
    @@test_file_dec = './test_file_dec'

  def _create_test_file
    File.open(@@test_file_in, 'w') do |f| f.write(@@test_buffer) end
    assert File.exists?(@@test_file_in)
  end

  def _compare_file
    plain_text_length = File.stat(@@test_file_dec).size
    plain_text = ''
    File.open(@@test_file_dec, 'r') do |f|
      plain_text = f.read(plain_text_length)
    end
    assert_equal @@test_buffer, plain_text
  end

  def _cleanup
    FileUtils.remove(@@test_file_in)
    FileUtils.remove(@@test_file_enc)
    FileUtils.remove(@@test_file_dec)
  end

  def test_that_it_has_a_version
    refute_nil ::KeyziioClient::VERSION
  end

  def test_initialization
    assert KZClient.new(@@keychain_id, @@access_token)
  end

  def test_session_key
    kzclient = KZClient.new(@@keychain_id, @@access_token)
    assert kzclient.get_session_key
  end

  def test_initialization_with_keychain_key
    assert KZClient.new(@@keychain_id, @@access_token, Base64.decode64(@@keychain_key))
  end

  def test_session_already_initialized
    kzclient = KZClient.new(@@keychain_id, @@access_token, Base64.decode64(@@keychain_key))
    assert_raise SessionAlreadyInitialized do
      kzclient.get_session_key
    end
  end

  def test_construct_keychain_key
    kzclient = KZClient.new(@@keychain_id, @@access_token, Base64.decode64(@@keychain_key))
    assert_equal Base64.decode64(@@keychain_key), kzclient.construct_keychain_key('')
  end

  def test_get_keychain_key
    kzclient = KZClient.new(@@keychain_id, @@access_token)
    session_key = kzclient.get_session_key
    kzrestclient = KZRestClient.new(@@keychain_id, @@access_token, @@server_url)
    assert kzrestclient.get_keychain_key(session_key)
  end

  def test_encrypt_buffer_uninitialized_keychain_key
    kz_user = KZClient.new(@@keychain_id, @@access_token)
    assert_raise UnInitializedKeychainKey do
      kz_user.encrypt_buffer(@@test_buffer, SecureRandom::uuid)
    end
  end

  def test_encrypt_buffer
    kz_user = KZClient.new(@@keychain_id, @@access_token, Base64.decode64(@@keychain_key))
    assert_not_nil kz_user.encrypt_buffer(@@test_buffer, SecureRandom::uuid)
  end

  def test_decrypt_buffer
    kz_user = KZClient.new(@@keychain_id, @@access_token, Base64.decode64(@@keychain_key))
    decrypted_buffer = kz_user.decrypt_buffer(@@encrypted_buffer)
    assert_equal @@test_buffer, decrypted_buffer
  end

  def test_encrypt_decrypt_buffer
    kz_user = KZClient.new(@@keychain_id, @@access_token, Base64.decode64(@@keychain_key))
    encrypted_buffer = kz_user.encrypt_buffer(@@blocksize_buffer, SecureRandom::uuid)
    assert_not_nil encrypted_buffer
    decrypted_buffer = kz_user.decrypt_buffer(encrypted_buffer)
    assert_equal @@blocksize_buffer, decrypted_buffer
  end

  def test_encrypt_decrypt_file
    _create_test_file
    kz_user = KZClient.new(@@keychain_id, @@access_token, Base64.decode64(@@keychain_key))
    kz_user.encrypt_file(@@test_file_in, @@test_file_enc, SecureRandom::uuid)
    assert File.exists?(@@test_file_enc)
    kz_user.decrypt_file(@@test_file_enc, @@test_file_dec)
    assert File.exists?(@@test_file_dec)
    _compare_file
    _cleanup
  end
end