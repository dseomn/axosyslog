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

#include "grpc-certificate-verifier.hpp"

#include <grpcpp/grpcpp.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <utility>
#include <vector>

namespace syslogng {
namespace grpc {

HashCertificateVerifier() : md(NULL) {}

~HashCertificateVerifier()
{
  EVP_MD_free(md);
  md = NULL;
}

bool
HashCertificateVerifier::initialize(const char *hash_algorithm,
                                    std::vector<std::vector<uint8_t>>&& trusted_certificate_hashes)
{
  md = EVP_MD_fetch(NULL, hash_algorithm, NULL);
  if (!md) return false;
  this->trusted_certificate_hashes = std::move(trusted_certificate_hashes);
}

bool
HashCertificateVerifier::Verify(::grpc::experimental::TlsCustomVerificationCheckRequest* request,
                                std::function<void(grpc::Status)> callback,
                                ::grpc::Status* sync_status) const
{
  if (!md)
    {
      *sync_status = ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION, "HashCertificateVerifier not initialized");
      return true;
    }

  auto peer_cert = request->peer_cert();
  // TODO: do we need to verify that the peer actually has the private key associated with peer_cert?
  // TODO: is peer_cert in DER form?
  unsigned char peer_hash[EVP_MAX_MD_SIZE];
  unsigned int peer_hash_size;
  if (!EVP_Digest(peer_cert.data(), peer_cert.size(), peer_hash, &peer_hash_size, md, NULL))
    {
      *sync_status = ::grpc::Status(::grpc::StatusCode::INTERNAL, "HashCertificateVerifier: EVP_Digest failed");
      return true;
    }

  for (const auto& trusted_hash : trusted_certificate_hashes)
    {
      if (trusted_hash.size() == peer_hash_size && CRYPTO_memcmp(trusted_hash.data(), peer_hash, peer_hash_size) == 0)
        {
          *sync_status = ::grpc::Status::OK;
          return true;
        }
    }
  *sync_status = ::grpc::Status(::grpc::StatusCode::PERMISSION_DENIED, "certificate not in hash allowlist");
  return true;
}

}
}
