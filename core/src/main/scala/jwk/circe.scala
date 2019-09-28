package jwk

import java.net.URI
import java.util.Base64

import io.circe.{Decoder, DecodingFailure}
import jwk.Jwk._
import JWKPublicKey._
import cats.syntax.functor._

object circe {
  implicit val uriDecoder: Decoder[URI] = Decoder[String].map(URI.create)
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

  implicit val rsaPublicKeyDecoder: Decoder[RSA] = Decoder.instance { c =>
    for {
      _         <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "RSA", "Not an RSA key type"))
      id        <- c.downField("kid").as[String].map(Id)
      alg       <- c.downField("alg").as[RSA.Algorithm]
      use       <- c.downField("use").as[Option[Use]]
      exponent  <- c.downField("e").as[BigInt]
      modulus   <- c.downField("n").as[BigInt]
      x5u       <- c.downField("x5u").as[Option[URI]]
      x5t       <- c.downField("x5t").as[Option[String]]
      publicKey <- RSA.publicKey(modulus, exponent).left.map(e => DecodingFailure.fromThrowable(e, c.history))
    } yield RSA(id, alg, publicKey, use, x5u, x5t)
  }

  implicit val ecPublicKeyDecoder: Decoder[EC] = Decoder.instance { c =>
    for {
      _         <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "EC", "Not an EC key type"))
      id        <- c.downField("kid").as[String].map(Id)
      curve     <- c.downField("crv").as[EC.Algorithm]
      use       <- c.downField("use").as[Option[Use]]
      x         <- c.downField("x").as[BigInt]
      y         <- c.downField("y").as[BigInt]
      x5u       <- c.downField("x5u").as[Option[URI]]
      x5t       <- c.downField("x5t").as[Option[String]]
      publicKey <- EC.publicKey(x, y, curve).left.map(e => DecodingFailure.fromThrowable(e, c.history))
    } yield EC(id, curve, publicKey, use, x5u, x5t)
  }

  implicit val publicKeyDecoder: Decoder[JWKPublicKey[_]] = {
    rsaPublicKeyDecoder.widen[JWKPublicKey[_]].or(ecPublicKeyDecoder.widen[JWKPublicKey[_]])
  }

  implicit val jwkDecoder: Decoder[Jwk] = publicKeyDecoder.widen[Jwk]

  implicit val jwkSetDecoder: Decoder[JwkSet] = Decoder.instance(c => c.downField("keys").as[Set[Jwk]].map(JwkSet))
}
