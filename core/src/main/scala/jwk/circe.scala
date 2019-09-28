package jwk

import java.io.ByteArrayInputStream
import java.net.URI
import java.security.PublicKey
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.interfaces.ECPublicKey
import java.util.Base64

import io.circe.{Decoder, DecodingFailure, HCursor}
import jwk.Jwk._
import JWKPublicKey._
import cats.syntax.functor._
import scodec.bits.ByteVector

import scala.util.Try

object circe {
  implicit val uriDecoder: Decoder[URI]                = Decoder[String].map(URI.create)
  implicit val BigIntBigEndianDecoder: Decoder[BigInt] = Decoder[String].map(n => BigInt(1, Base64.getUrlDecoder.decode(n)))
  implicit val rsaAlgDecoder: Decoder[RSA.Algorithm] = Decoder[String].emap { alg =>
    RSA.Algorithm.values.find(_.jose == alg).toRight(s"$alg is not supported")
  }

  implicit val useDecoder: Decoder[Use] = Decoder[String].map {
    case "sig" => Use.Signature
    case "enc" => Use.Encryption
    case e     => Use.Extension(e)
  }

  implicit val curveDecoder: Decoder[EC.Algorithm] = Decoder[String].emap { alg =>
    EC.Algorithm.values.find(_.jose == alg).toRight(s"$alg is not supported")
  }

  implicit val byteVectorDecoder: Decoder[ByteVector] = Decoder[String].emap(s => ByteVector.fromBase64Descriptive(s))
  implicit val x509CertificateDecoder: Decoder[X509Certificate] =
    Decoder[ByteVector].emapTry { s =>
      Try {
        val factory = CertificateFactory.getInstance("X.509")
        factory.generateCertificate(new ByteArrayInputStream(s.toArray)).asInstanceOf[X509Certificate]
      }
    }

  implicit val x509Decoder: Decoder[Option[X509]] = Decoder.instance { c =>
    for {
      x5u    <- c.downField("x5u").as[Option[URI]]
      x5t    <- c.downField("x5t").as[Option[ByteVector]]
      x5t256 <- c.downField("x5t#S256").as[Option[ByteVector]]
      x5c    <- c.downField("x5c").as[Option[List[X509Certificate]]]
    } yield {
      x5u.map(url => X509Url(url, x5t, x5t256)).orElse(x5c.map(list => X509Chain(list, x5t, x5t256)))
    }
  }

  implicit val rsaPublicKeyDecoder: Decoder[RSA] = Decoder.instance { c =>
    for {
      _         <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "RSA", "Not an RSA key type"))
      id        <- c.downField("kid").as[String].map(Id)
      alg       <- c.downField("alg").as[Option[RSA.Algorithm]]
      use       <- c.downField("use").as[Option[Use]]
      exponent  <- c.downField("e").as[BigInt]
      modulus   <- c.downField("n").as[BigInt]
      x509      <- x509Decoder(c)
      publicKey <- RSA.publicKey(modulus, exponent).left.map(e => DecodingFailure.fromThrowable(e, c.history))
      validPk   <- validate(x509, c, publicKey)
    } yield RSA(id, alg, validPk, use, x509)
  }

  implicit val ecPublicKeyDecoder: Decoder[EC] = Decoder.instance { c =>
    for {
      _         <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "EC", "Not an EC key type"))
      id        <- c.downField("kid").as[String].map(Id)
      curve     <- c.downField("crv").as[EC.Algorithm]
      use       <- c.downField("use").as[Option[Use]]
      x         <- c.downField("x").as[BigInt]
      y         <- c.downField("y").as[BigInt]
      x509      <- x509Decoder(c)
      publicKey <- EC.publicKey(x, y, curve).left.map(e => DecodingFailure.fromThrowable(e, c.history))
      validPk   <- validate(x509, c, publicKey)
    } yield EC(id, curve, validPk, use, x509)
  }

  private def validate[K <: PublicKey](x509: Option[X509], cursor: HCursor, publicKey: K): Decoder.Result[K] = {
    x509
      .map(cert => cert.validateHash(publicKey))
      .getOrElse(Right(publicKey))
      .left
      .map(e => DecodingFailure.fromThrowable(e, cursor.history))
  }

  implicit val publicKeyDecoder: Decoder[JWKPublicKey[_]] = {
    rsaPublicKeyDecoder.widen[JWKPublicKey[_]].or(ecPublicKeyDecoder.widen[JWKPublicKey[_]])
  }

  implicit val jwkDecoder: Decoder[Jwk] = publicKeyDecoder.widen[Jwk]

  implicit val jwkSetDecoder: Decoder[JwkSet] = Decoder.instance(c => c.downField("keys").as[Set[Jwk]].map(JwkSet))
}
