package jwk

import java.net.URI
import java.security.PublicKey
import java.security.cert.{CertificateException, X509Certificate}

import scodec.bits.ByteVector

trait X509 {
  def sha1: Option[ByteVector]
  def sha256: Option[ByteVector]

  def validateHash[PK <: PublicKey](pk: PK): Either[CertificateException, PK] = {
    val encoded  = ByteVector(pk.getEncoded)
    val sha1PK   = encoded.digest("SHA-1")
    val sha256PK = encoded.digest("SHA-256")
    (sha1.forall(_ == sha1PK), sha256.forall(_ == sha256PK)) match {
      case (true, true)   => Right(pk)
      case (false, true)  => Left(new CertificateException("Did not match SHA-1 Hash"))
      case (true, false)  => Left(new CertificateException("Did not match SHA-256 Hash"))
      case (false, false) => Left(new CertificateException("Didnt match any of the hashes"))
    }
  }
}

case class X509Url(url: URI, sha1: Option[ByteVector], sha256: Option[ByteVector])                     extends X509
case class X509Chain(x5c: List[X509Certificate], sha1: Option[ByteVector], sha256: Option[ByteVector]) extends X509
