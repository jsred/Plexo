require 'net/http'
require 'uri'

class SignPackage
  def initialize(url, send = true)
    @cert_path = "app/services/certificates/#{Rails.application.credentials[:plexo][:cert_name]}"
    @cert_password = Rails.application.credentials[:plexo][:password]
    @url = url
    @send = send

    @pkcs12 = OpenSSL::PKCS12.new(File.binread(@cert_path), @cert_password)
    @fingerprint = OpenSSL::Digest::SHA1.new(@pkcs12.certificate.to_der).to_s.upcase
    @pkey = OpenSSL::PKey::RSA.new(@pkcs12.key.to_pem)
    @digest = OpenSSL::Digest::SHA512.new
  end

  def call(data)
    @object = {
      'Fingerprint' => @fingerprint,
      'Object' => data,
      'UTCUnixTimeExpiration' => (Time.now.to_i + 10_000)
    }

    signature = Base64.encode64(@pkey.sign(@digest, @object.to_json.to_s))
    p '-------/ Paquete enviado \-------'

    p body = {
      'Object' => @object,
      'Signature' => signature.delete("\n")
    }

    
    if @send
      pack = body.to_json
      response = Net::HTTP.post URI(@url), pack, 'Content-Type' => 'application/json'
      p '-------/ Paquete recibido \-------'
      p json_response = JSON.parse(response.body)
    else
      return body
    end
      
  end
end
