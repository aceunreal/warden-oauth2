require 'warden-oauth2'

module Warden
  module OAuth2
    module Strategies
      class FacebookAccessToken < Client
        def valid?
          !!params['fb_access_token'] && params['grant_type'] == 'fb_access_token'
        end

        protected

        def model
          Warden::OAuth2.config.facebook_access_token_model
        end

        def client_authenticated
          token = params['fb_access_token']

          fail('invalid_token') && return unless token

          if client.valid?(fb_access_token: token)
            super
          else
            fail('invalid_token') && return
          end
        end
      end
    end
  end
end
