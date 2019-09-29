package jwk

import java.security.PublicKey

import scodec.bits.ByteVector

case class ValidationError(message: String)

object JwkValidator {
  type Result[A] = Either[ValidationError, A]
  def validate(jwk: Jwk): Result[Jwk] = {
    jwk match {
      case rsa: Jwk.RSA => validate(rsa.x509, rsa.publicKey).map(_ => rsa)
      case ec: Jwk.EllipticCurve   => validate(ec.x509, ec.publicKey).map(_ => ec)
    }
  }

  private def validate[K <: PublicKey](x509: Option[X509], publicKey: K): Either[ValidationError, K] = {
    x509
      .map(cert => validateHash(cert, publicKey))
      .getOrElse(Right(publicKey))
  }

  def validateHash[PK <: PublicKey](x509: X509, pk: PK): Either[ValidationError, PK] = {
    val encoded  = ByteVector(pk.getEncoded)
    val sha1PK   = encoded.digest("SHA-1")
    val sha256PK = encoded.digest("SHA-256")
    (x509.sha1.forall(_ == sha1PK), x509.sha256.forall(_ == sha256PK)) match {
      case (true, true)   => Right(pk)
      case (false, true)  => Left(ValidationError("Did not match SHA-1 Hash"))
      case (true, false)  => Left(ValidationError("Did not match SHA-256 Hash"))
      case (false, false) => Left(ValidationError("Didnt match any of the hashes"))
    }
  }

}
