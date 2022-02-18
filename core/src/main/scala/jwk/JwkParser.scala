package jwk

import java.security.PublicKey

import cats.data.NonEmptyList
import scodec.bits.ByteVector
import cats.implicits._
import io.circe.jawn
import jwk.circe._

sealed trait ParseError extends Exception

case class ValidationError(message: String) extends ParseError {
  override def getMessage: String = message
}

case class ParseErrors(errors: NonEmptyList[ParseError]) extends ParseError {
  override def getMessage: String = "Failed to validate:\n" + errors.map(_.getMessage).toList.mkString("\n")
}

case class DecodeError(message: String, cause: io.circe.Error) extends ParseError

object JwkParser {
  type Result[A] = Either[ParseError, A]
  def parse(input: String): Result[Jwk] =
    jawn.decode[Jwk](input).leftMap(DecodeError("Unable to decode jwk", _)).flatMap(validate)

  def parseSet(input: String): Result[JwkSet] = {
    val valid =
      jawn.decode[JwkSet](input).leftMap(DecodeError("Unable to decode JWKSet", _))

    valid.flatMap(set => set.keys.toList.traverse(validate(_).toValidatedNel).toEither.leftMap(ParseErrors.apply).as(set))
  }

  def parseAuth0Set(input: String): Result[JwkSet] =
    jawn.decode[JwkSet](input).leftMap(DecodeError("Unable to decode JWKSet", _))

  def validate(jwk: Jwk): Result[Jwk] =
    jwk match {
      case rsa: Jwk.RSA => validate(rsa.x509, rsa.publicKey).map(_ => rsa)
      case ec: Jwk.EllipticCurve => validate(ec.x509, ec.publicKey).map(_ => ec)
      case hmac: Jwk.HMac => Right(hmac)
    }

  private def validate[K <: PublicKey](x509: Option[X509], publicKey: K): Result[K] =
    x509
      .map(cert => validateHash(cert, publicKey))
      .getOrElse(Right(publicKey))

  def validateHash[PK <: PublicKey](x509: X509, pk: PK): Result[PK] = {
    val encoded = ByteVector(pk.getEncoded)
    val sha1PK = encoded.digest("SHA-1")
    val sha256PK = encoded.digest("SHA-256")
    (x509.sha1.forall(s => ByteEquality.equal(s, sha1PK)), x509.sha256.forall(s => ByteEquality.equal(s, sha256PK))) match {
      case (true, true) => Right(pk)
      case (false, true) => Left(ValidationError("Did not match SHA-1 Hash"))
      case (true, false) => Left(ValidationError("Did not match SHA-256 Hash"))
      case (false, false) => Left(ValidationError("Didnt match any of the hashes"))
    }
  }

}
