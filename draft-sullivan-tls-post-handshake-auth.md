---
title: Post-Handshake Authentication in TLS
abbrev: TLS Post-Handshake Auth
docname: draft-sullivan-tls-post-handshake-auth-latest
date: 2016-07
category: std

ipr:
area: Security
workgroup: TLS
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: N. Sullivan
    name: Nick Sullivan
    organization: CloudFlare Inc.
    email: nick@cloudflare.com

 -
    ins: M. Thomson
    name: Martin Thomson
    organization: Mozilla
    email: martin.thomson@gmail.com

 -
    ins: M. Bishop
    name: Mike Bishop
    organization: Microsoft
    email: michael.bishop@microsoft.com

normative:
  RFC3546:
  RFC6066:
  RFC6961:
  RFC6962:
  I-D.ietf-tls-tls13:

informative:



--- abstract

This document describes a mechanism for performing post-handshake certificate-based authentication in Transport Layer Security (TLS) versions 1.3 and later. This includes both spontaneous and elicited authentication of both client and server.

--- middle

# Introduction

This document defines a way to authenticate one party of a Transport Layer Security (TLS) communication to another using a certificate after the session has been established. This allows both the client and server to elicit proof of ownership of additional identities at any time after the handshake has completed. It also allows for both the client and server to spontaneously provide a certificate and proof of ownership of the private key to the other party.

This mechanism is useful in the following situations:

* servers that have the ability to serve requests from multiple domains over the same connection but do not have a certificate that is simultaneously authoritative over all of them
* servers that have resources that require client authentication to access and need to request client authentication after the connection has started
* clients that want to assert their identity to a server after a connection has been established
* clients that want a server to re-prove ownership of their private key during a connection or after a resumption
* clients that wish to ask a server to authenticate for a new domain not covered by the initial connection certificate 

This document intends to replace much of the functionality of secure renegotiation in previous versions of TLS. It has the advantages over secure renegotiation of only requiring one round trip and maintaining the same application keys during a connection.

This document describes four new post handshake authentication flows: client-triggered server authentication, spontaneous server authentication, server-triggered client authentication, and spontaneous client authentication. It also defines two new handshake extensions and several additional post-handshake messages, which mirror some of the messages in the TLS 1.3 handshake.

## TLS Extensions

We define a pair of new TLS extensions to advertise support for post-handshake authentication.

### Client Authentication Extensions

	enum { client_auth_elicited(0), client_auth_spontaneous(1), (255) } ClientAuthType; 
	struct {
	  ClientAuthType client_auth_types<0..2^16-1>;
	  select (Role) {
	    case server:
	      SignatureScheme supported_signature_algorithms<2..2^16-2>
	  }
	} ClientAuth;

The client advertises every type of client authentication it supports in ClientAuth extension in its ClientHello. The server replies with an EncryptedExtensions containing a ClientAuth extension containing a list of client authentication types and the list of signature schemes supported. The set of ClientAuthTypes in the server’s ClientAuth extension MUST be a subset of the set sent by the client. The extension MAY be omitted if the server does not support any form of post-handshake client authentication.

### Server Authentication Extensions

The ServerAuth hello extension is used to negotiate support for post-handshake server authentication.

	enum { server_auth_elicited(0), server_auth_spontaneous(1), (255) } ServerAuthType; 
	struct {
	  ServerAuthType server_auth_types<0..2^16-1>;
	} ServerAuth;

   The client advertises every type of server authentication it supports in its ClientHello. The server replies with EncryptedExtensions containing a ServerAuth extension containing a list of server authentication types. The set of ServerAuthTypes in the server’s ServerAuth extension MUST be a subset of the set sent by the client. The extension MAY be omitted if the server does not support any form of post-handshake server authentication.

## Post-Handshake Authentication Messages

The messages used for post-handshake authentication closely mirror those used to authenticate certificates in the standard TLS handshake.

### Certificate Request

For elicited post-handshake authentication, the first message is used to define the characteristics required in the elicited certificate.

opaque DistinguishedName<1..2^16-1>;

	struct {
	  opaque certificate_extension_oid<1..2^8-1>;
	  opaque certificate_extension_values<0..2^16-1>;
	} CertificateExtension;
	
	struct {
	  opaque certificate_request_context<0..2^8-1>;
	  select (Role) {
	    case server:
	      DistinguishedName certificate_authorities<0..2^16-1>;
	      CertificateExtension certificate_extensions<0..2^16-1>;
	    case client:
	      ServerNameList server_name_list;
	  }
	} CertificateRequest;

The certificate_request_context is an opaque string which identifies the certificate request and which will be echoed in the corresponding Certificate message.

For CertificateRequests sent from the server, the DistinguishedName and CertificateExtension fields are defined exactly as in the TLS 1.3 specification. For CertificateRequests send from the client, a ServerNameList containing the subject name indication used for selecting the certificate is included. The structure of this field is defined in RFC 3546 [RFC3546].

### Certificate Message

The certificate message is used to transport the certificate. It mirrors the Certificate message in the TLS with the addition of some certificate-specific extensions.

	opaque ASN1Cert<1..2^24-1>;
	
	struct {
	  opaque certificate_request_context<0..2^8-1>;
	  ASN1Cert certificate_list<0..2^24-1>;
	  struct {
	    Extension extensions<0..2^16-1>;
	  } Extensions;
	} Certificate;

Valid extensions include OCSP Status extensions ([RFC6066] and [RFC6961]) and SignedCertificateTimestamps ([RFC6962]). These extension MUST only be presented if the handshake negotiation permits these extensions to be presented in the EncryptedExtensions message.

The certificate_request_context is an opaque string that identifies the certificate. If the certificate is used in response to a CertificateRequest, it MUST mirror the certificate_request_context sent in the CertificateRequest. If the Certificate message is part of an elicited authentication, the certificate_request_context is chosen uniquely by the sender.  Exchanges initiated by the client use odd-numbered certificate_request_context values, while exchanges initiated by the server use even-numbered certificate_request_context values.

### CertificateVerify Message

The CertificateVerify message used in this document is defined in section 4.3.2. of the TLS 1.3 specification.

	struct {
	  SignatureScheme algorithm;
	  opaque signature<0..2^16-1>;
	} CertificateVerify;

The algorithm field specifies the signature algorithm used (see Section 4.2.2 of TLS 1.3). The signature is a digital signature using that algorithm that covers the hash output:

	Hash(Handshake Context + Certificate) + Hash(resumption_context)

The Handshake context and Base Key are defined in the following table

| Mode | Handshake Context | Base Key |
|------|-------------------|----------|
| Spontaneous Authentication | ClientHello ... ClientFinished | traffic_secret_N |
| Elicited Authentication | ClientHello ... ClientFinished + CertificateRequest | traffic_secret_N |

### Finished Message

Finished is a MAC over the value Hash(Handshake Context + Certificate + CertificateVerify) + Hash(resumption_context) using a MAC key derived from the base key.

## Post-Handshake Authentication Flows

There are four post-handshake authentication exchanges.

### Elicited Client Authentication Flow

This flow is initiated by a CertificateRequest message from the server to the client with an even-valued certificate_request_context. It MUST only be sent if the server’s EncryptedExtensions contains a ClientAuth extension. Upon receiving a CertificateRequest message, the client SHOULD respond with a contiguous sequence:

Certificate, CertificateVerify, Finished

or MAY respond with the sequence:

Certificate, Finished

where the Certificate message has an empty certificate_list field. The Certificate message MUST contain the same certificate_request_context as the CertificateRequest message. Non-empty Certificate messages SHOULD conform to the certificate_authorities and certificate_extensions sent in the CertificateRequest.

	<- CertificateRequest
	-> Certificate, CertificateVerify, Finished

Because client authentication may require prompting the user, servers MUST be prepared for some delay, including receiving an arbitrary number of other messages between sending the CertificateRequest and receiving a response. In addition, clients which receive multiple CertificateRequests in close succession MAY respond to them in a different order than they were received (the certificate_request_context value allows the server to disambiguate the responses).

### Spontaneous Client Authentication Flow

This flow is initiated by a contiguous sequence of Certificate, CertificateVerify, Finished message from the client to the server. The Certificate message MUST contain an odd-valued certificate_request_context so as not to collide with an elicited client authentication. The Certificate message SHOULD conform to the SignatureSchemes presented in the ClientAuth extension from the server’s EncryptedExtensions message.

	-> Certificate, CertificateVerify, Finished

### Elicited Server Authentication Flow

This flow is initiated by a CertificateRequest message from the client to the server. The CertificateRequest MUST contain an odd-valued certificate_request_context. Upon receiving a CertificateRequest message, the server SHOULD respond with a contiguous sequence of:

Certificate, CertificateVerify, Finished

or MAY respond with the sequence:

Certificate, Finished

where the Certificate message has an empty certificate_list field. The Certificate message MUST contain the same certificate_request_context as the CertificateRequest message. The Certificate message SHOULD conform to the ServerNameList sent in the CertificateRequest and the SignatureSchemes presented in the ClientHello.

	-> CertificateRequest
	<- Certificate, CertificateVerify, Finished

Clients MUST be prepared for some delay, including receiving an arbitrary number of other messages between sending the CertificateRequest and receiving a response. In addition, servers which receive multiple CertificateRequests in close succession MAY respond to them in a different order than they were received (the certificate_request_context value allows the server to disambiguate the responses).

### Spontaneous Server Authentication Flow

This flow is initiated by a contiguous sequence of Certificate, CertificateVerify, Finished message from the server to the client. The Certificate message MUST contain an even-valued certificate_request_context so as not to collide with an elicited server authentication. The Certificate message MUST conform to the SignatureSchemes presented in the ClientHello.

	<- Certificate, CertificateVerify, Finished

## Interaction between resumption

Certificate identities established post-handshake should not be maintained across resumption. If a connection is resumed, additional certificate identities for both client and server certificates MUST NOT be automatically persisted, but MAY be elicited again immediately post-handshake.

# Acknowledgements {#ack}

Eric Rescorla and Andrei Popov contributed to this draft.

--- back
