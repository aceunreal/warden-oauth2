require 'spec_helper'

describe Warden::OAuth2::Strategies::FacebookAccessToken do
  let(:strategy) { described_class }
  let(:client_model) { double(:ClientApplication) }
  subject { strategy.new('rack.input' => {}) }

  before do
    Warden::OAuth2.config.facebook_access_token_model = client_model
  end

  describe '#valid?' do
    it 'returns false if the grant type is not specified' do
      allow(subject).to receive(:params).and_return({'fb_access_token' => 'some_token'})
      expect(subject).to_not be_valid
    end

    it 'returns false if the fb_access_token is not specified' do
      allow(subject).to receive(:params).and_return({'grant_type' => 'fb_access_token'})
      expect(subject).to_not be_valid
    end

    it 'returns true if the grant type is fb_access_token' do
      allow(subject).to receive(:params).and_return({'grant_type' => 'fb_access_token', 'fb_access_token' => 'some_token'})
      expect(subject).to be_valid
    end

    it 'returns false if the grant type is not fb_access_token' do
      allow(subject).to receive(:params).and_return('grant_type' => 'whatever', 'fb_access_token' => 'some_token')
      expect(subject).to_not be_valid
    end
  end

  describe '#authenticate!' do
    it 'should fail when the client is around but not valid' do
      client_instance = double(:client_instance, valid?: false)
      allow(client_model).to receive_messages(locate: client_instance)
      allow(subject).to receive(:params).and_return({'client_id' => 'awesome', 'grant_type' => 'fb_access_token', 'fb_access_token' => 'some_token'})
      subject._run!
      expect(subject.error_status).to eq(401)
      expect(subject.message).to eq('invalid_token')
    end

    it 'should fail if access token is not provided' do
      allow(client_model).to receive_messages(locate: double)
      allow(subject).to receive(:params).and_return({'client_id' => 'awesome', 'grant_type' => 'fb_access_token'})
      subject._run!
      expect(subject.error_status).to eq(401)
      expect(subject.message).to eq('invalid_token')
    end

    it 'should succeed if client is around and valid' do
      client_instance = double(:client_instance, valid?: true)
      allow(client_model).to receive_messages(locate: client_instance)
      allow(subject).to receive(:params).and_return({'client_id' => 'awesome', 'grant_type' => 'fb_access_token', 'fb_access_token' => 'some_token'})
      subject._run!
      expect(subject.user).to eq(client_instance)
      expect(subject.result).to eq(:success)
    end
  end
end
