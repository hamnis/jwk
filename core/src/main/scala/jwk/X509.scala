package jwk

import java.net.URI
import java.security.PublicKey
import java.security.cert.{CertificateException, X509Certificate}

import scodec.bits.ByteVector

trait X509 {
  def sha1: Option[ByteVector]
  def sha256: Option[ByteVector]
}

case class X509Url(url: URI, sha1: Option[ByteVector], sha256: Option[ByteVector])                     extends X509
case class X509Chain(x5c: List[X509Certificate], sha1: Option[ByteVector], sha256: Option[ByteVector]) extends X509
