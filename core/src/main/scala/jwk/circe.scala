package jwk

import java.io.ByteArrayInputStream
import java.net.URI
import java.security.KeyFactory
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.interfaces.RSAPrivateKey
import java.security.spec.RSAPrivateCrtKeySpec
import java.util.Base64

import io.circe.{Decoder, DecodingFailure, HCursor}
import jwk.Jwk._
import cats.implicits._
import scodec.bits.ByteVector

import scala.util.Try

object circe {
  implicit val byteVectorDecoder: Decoder[ByteVector] = Decoder[String].emap(s => ByteVector.fromBase64Descriptive(s))

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

  implicit val curveDecoder: Decoder[EC.Curve] = Decoder[String].emap { alg =>
    EC.Curve.values.find(_.jose == alg).toRight(s"$alg is not supported")
  }

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

  def rsaSpec(
      publicModulus: BigInt,
      publicExponent: BigInt,
      privateExponent: BigInt,
      primeP: BigInt,
      primeQ: BigInt,
      primeExponentP: BigInt,
      primeExponentQ: BigInt,
      crtCoefficient: BigInt
  ) =
    new RSAPrivateCrtKeySpec(
      publicModulus.bigInteger,
      publicExponent.bigInteger,
      privateExponent.bigInteger,
      primeP.bigInteger,
      primeQ.bigInteger,
      primeExponentP.bigInteger,
      primeExponentQ.bigInteger,
      crtCoefficient.bigInteger
    )

  private def rsaPrivateKey(exponent: BigInt, modulus: BigInt, c: HCursor): Decoder.Result[Option[RSAPrivateKey]] = {
    for {
      d  <- c.downField("d").as[Option[BigInt]]
      p  <- c.downField("p").as[Option[BigInt]]
      q  <- c.downField("q").as[Option[BigInt]]
      dp <- c.downField("dp").as[Option[BigInt]]
      dq <- c.downField("dq").as[Option[BigInt]]
      qi <- c.downField("qi").as[Option[BigInt]]
      pk <- Try {
             val factory = KeyFactory.getInstance("RSA")
             (Some(modulus), Some(exponent), d, p, q, dp, dq, qi)
               .mapN(rsaSpec)
               .map(factory.generatePrivate(_).asInstanceOf[RSAPrivateKey])
           }.fold(e => Left(DecodingFailure.fromThrowable(e, c.history)), Right(_))
    } yield pk
  }

  implicit val rsaPublicKeyDecoder: Decoder[RSA] = Decoder.instance { c =>
    for {
      _          <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "RSA", "Not an RSA key type"))
      id         <- c.downField("kid").as[String].map(Id)
      alg        <- c.downField("alg").as[Option[RSA.Algorithm]]
      use        <- c.downField("use").as[Option[Use]]
      exponent   <- c.downField("e").as[BigInt]
      modulus    <- c.downField("n").as[BigInt]
      privateKey <- rsaPrivateKey(exponent, modulus, c)
      publicKey  <- RSA.publicKey(modulus, exponent).left.map(e => DecodingFailure.fromThrowable(e, c.history))
      x509       <- x509Decoder(c)
    } yield RSA(id, alg, publicKey, privateKey, use, x509)
  }

  implicit val ecPublicKeyDecoder: Decoder[EC] = Decoder.instance { c =>
    for {
      _         <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "EC", "Not an EC key type"))
      id        <- c.downField("kid").as[String].map(Id)
      curve     <- c.downField("crv").as[EC.Curve]
      use       <- c.downField("use").as[Option[Use]]
      x         <- c.downField("x").as[BigInt]
      y         <- c.downField("y").as[BigInt]
      x509      <- x509Decoder(c)
      publicKey <- EC.publicKey(x, y, curve).left.map(e => DecodingFailure.fromThrowable(e, c.history))
    } yield EC(id, curve, publicKey, use, x509)
  }

  implicit val publicKeyDecoder: Decoder[JWKPublicKey[_]] = {
    rsaPublicKeyDecoder.widen[JWKPublicKey[_]].or(ecPublicKeyDecoder.widen[JWKPublicKey[_]])
  }

  implicit val jwkDecoder: Decoder[Jwk] = publicKeyDecoder.widen[Jwk]

  implicit val jwkSetDecoder: Decoder[JwkSet] = Decoder.instance(c => c.downField("keys").as[Set[Jwk]].map(JwkSet))
}
