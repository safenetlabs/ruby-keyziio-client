require 'logger'
require 'json'
require 'rest-client'

class Unauthorized < Exception
  # Unauthorized to get resource
end

class ConnectionFailure < Exception
  # Not connected to the server at all
end

class ResourceNotFound < Exception
  # Failed to get resource from keyziio server
end


class KZRestClient < Object
  attr_accessor :token_hash

    def initialize (client_id, client_secret, keychain_id, server_url='https://keyziio2.herokuapp.com')
      @base_url = server_url
      @user = client_id
      @password = client_secret
      @keychain_id = keychain_id
      @data_key_path = 'api/v1/client/keychain/'
      @user_key_path = 'api/v1/client/keychains/'
      begin
        self.check_or_get_token # Not really necessary here, but why not get it early.  Ignore expected exceptions
      rescue SocketError, RestClient::Unauthorized
        true
      end
    end

    def check_or_get_token
      if !(self.token_hash).nil?
        return true # already have one
      end

      uri = URI.parse("#{@base_url}/api/v1/oauth2/token")
      uri.user = @user
      uri.password = @password
      response = RestClient.post(uri.to_s , {:grant_type => 'client_credentials'}.to_json,
                                 {:content_type => :json, :accept => :json})
      self.token_hash = JSON.parse(response)
    end

    def _url (path)
      return '%s/%s' % [@base_url, path]
    end

    def get_user_key (pub_key_pem)
      self.check_or_get_token
      begin
        RestClient.get _url(@user_key_path + @keychain_id.to_s + '/wrap'), {:params => {'public_key' => pub_key_pem},
                                              :content_type => :json,
                                              :accept => :json,
                                              :user_agent => 'Keyziio Ruby Client',
                                              :authorization => "Bearer #{self.token_hash['access_token']}"}
      rescue RestClient::Unauthorized
        raise Unauthorized
      rescue SocketError => e
        raise ConnectionFailure, e.message
      rescue RestClient::ResourceNotFound => e
        raise ResourceNotFound, e.message
      end
    end

    def get_key (key_id)
      self.check_or_get_token
      begin
        RestClient.get _url(@data_key_path + @keychain_id.to_s + '/data_keys/' + key_id.to_s),
                       {:content_type => :json,
                        :accept => :json,
                        :user_agent => 'Keyziio Ruby Client',
                        :authorization => "Bearer #{self.token_hash['access_token']}"}
      rescue RestClient::Unauthorized
        raise Unauthorized
      rescue SocketError => e
        raise ConnectionFailure, e.message
      rescue RestClient::ResourceNotFound => e
        raise ResourceNotFound, e.message
      end
    end

    def post_data_key (key_name, key_type, key, iv)
      self.check_or_get_token
      begin
        RestClient.post _url(@data_key_path + @keychain_id.to_s + '/data_keys'), {'name' => key_name,
                                                                                 'type' => key_type,
                                                                                 'key' => key,
                                                                                 'iv' => iv},
                                                                                :content_type => :json,
                                                                                :accept => :json,
                                                                                :user_agent => 'Keyziio Ruby Client',
                                                                                :authorization => "Bearer #{self.token_hash['access_token']}"
      rescue RestClient::Unauthorized
        raise Unauthorized
      rescue SocketError => e
        raise ConnectionFailure, e.message
      end
    end
end

if __FILE__ == $0
  rc = KZRestClient.new()
  #resp = rc.get_key('my_test_key_1', 'c87f689e-85d5-46b3-81ba-ce9666371d45')
  resp = rc.get_key('my_test_key_1')
  print resp ? resp : 'not found'
end
