/*
 * Copyright (c) 2025 David Mandelberg
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * As an additional exemption you are allowed to compile & link against the
 * OpenSSL libraries as published by the OpenSSL project. See the file
 * COPYING for details.
 *
 */

#ifndef GRPC_CERTIFICATE_VERIFIER_HPP
#define GRPC_CERTIFICATE_VERIFIER_HPP

#include <grpcpp/grpcpp.h>
#include <grpcpp/security/tls_certificate_verifier.h>
#include <openssl/evp.h>

#include <vector>

namespace syslogng {
namespace grpc {

class HashCertificateVerifier : public ::grpc::experimental::ExternalCertificateVerifier
{
public:
  HashCertificateVerifier();
  ~HashCertificateVerifier();

  bool initialize(const char *hash_algorithm, std::vector<std::vector<uint8_t>>&& trusted_certificate_hashes);

  bool Verify(::grpc::experimental::TlsCustomVerificationCheckRequest* request,
              std::function<void(grpc::Status)> callback, ::grpc::Status* sync_status) override const;

private:
  EVP_MD *md;
  std::vector<std::vector<uint8_t>> trusted_certificate_hashes;
};

}
}

#endif
