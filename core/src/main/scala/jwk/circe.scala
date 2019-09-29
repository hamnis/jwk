package jwk

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.net.URI
import java.security.KeyFactory
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.interfaces.{ECPrivateKey, ECPublicKey, RSAPrivateKey, RSAPublicKey}
import java.security.spec.{ECPoint, ECPrivateKeySpec, ECPublicKeySpec, RSAPrivateCrtKeySpec, RSAPublicKeySpec}
import java.util.Base64

import io.circe.{Decoder, DecodingFailure, HCursor}
import jwk.Jwk._
import cats.implicits._
import scodec.bits.ByteVector

import scala.util.Try

object circe {
  implicit val byteVectorDecoder: Decoder[ByteVector] = Decoder[String].emap(s => ByteVector.fromBase64Descriptive(s))

  implicit val uriDecoder: Decoder[URI] = Decoder[String].map(URI.create)
  implicit val BigIntBigEndianDecoder: Decoder[BigInteger] =
    Decoder[String].map(n => BigInt(1, Base64.getUrlDecoder.decode(n)).bigInteger)
  implicit val rsaAlgDecoder: Decoder[RSA.Algorithm] = Decoder[String].emap { alg =>
    RSA.Algorithm.values.find(_.jose == alg).toRight(s"$alg is not supported")
  }

  def tryDecode[A](c: HCursor, tried: Try[A]): Decoder.Result[A] =
    tried.toEither.leftMap(e => DecodingFailure.fromThrowable(e, c.history))

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

  private def rsa(c: HCursor): Decoder.Result[(RSAPublicKey, Option[RSAPrivateKey])] = {
    for {
      n       <- c.downField("n").as[BigInteger]
      e       <- c.downField("e").as[BigInteger]
      d       <- c.downField("d").as[Option[BigInteger]]
      p       <- c.downField("p").as[Option[BigInteger]]
      q       <- c.downField("q").as[Option[BigInteger]]
      dp      <- c.downField("dp").as[Option[BigInteger]]
      dq      <- c.downField("dq").as[Option[BigInteger]]
      qi      <- c.downField("qi").as[Option[BigInteger]]
      factory <- tryDecode(c, Try { KeyFactory.getInstance("RSA") })
      public  <- tryDecode(c, Try { factory.generatePublic(new RSAPublicKeySpec(n, e)).asInstanceOf[RSAPublicKey] })
      priv <- tryDecode(
               c,
               Try {
                 (Some(n), Some(e), d, p, q, dp, dq, qi)
                   .mapN(new RSAPrivateCrtKeySpec(_, _, _, _, _, _, _, _))
                   .map(factory.generatePrivate(_).asInstanceOf[RSAPrivateKey])
               }
             )
    } yield (public, priv)
  }

  implicit val rsaDecoder: Decoder[RSA] = Decoder.instance { c =>
    for {
      _    <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "RSA", "Not an RSA key type"))
      id   <- c.downField("kid").as[String].map(Id)
      alg  <- c.downField("alg").as[Option[RSA.Algorithm]]
      use  <- c.downField("use").as[Option[Use]]
      rsa  <- rsa(c)
      x509 <- x509Decoder(c)
    } yield RSA(id, alg, rsa._1, rsa._2, use, x509)
  }

  implicit val ecDecoder: Decoder[EC] = Decoder.instance { c =>
    for {
      _     <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "EC", "Not an EC key type"))
      id    <- c.downField("kid").as[String].map(Id)
      curve <- c.downField("crv").as[EC.Curve]
      use   <- c.downField("use").as[Option[Use]]
      ec    <- ec(c, curve)
      x509  <- x509Decoder(c)
    } yield EC(id, curve, ec._1, ec._2, use, x509)
  }

  def ec(c: HCursor, curve: EC.Curve): Decoder.Result[(ECPublicKey, Option[ECPrivateKey])] = {
    for {
      x     <- c.downField("x").as[BigInteger]
      y     <- c.downField("y").as[BigInteger]
      d     <- c.downField("d").as[Option[BigInteger]]
      point = new ECPoint(x, y)
      kf    <- tryDecode(c, Try { KeyFactory.getInstance("EC") })
      pk    <- tryDecode(c, Try { kf.generatePublic(new ECPublicKeySpec(point, curve.spec)).asInstanceOf[ECPublicKey] })
      priv <- tryDecode(c, Try {
               d.map(priv => kf.generatePrivate(new ECPrivateKeySpec(priv, curve.spec)).asInstanceOf[ECPrivateKey])
             })
    } yield (pk, priv)
  }

  implicit val publicKeyDecoder: Decoder[JWKPublicKey[_]] = {
    rsaDecoder.widen[JWKPublicKey[_]].or(ecDecoder.widen[JWKPublicKey[_]])
  }

  implicit val jwkDecoder: Decoder[Jwk] = publicKeyDecoder.widen[Jwk]

  implicit val jwkSetDecoder: Decoder[JwkSet] = Decoder.instance(c => c.downField("keys").as[Set[Jwk]].map(JwkSet))
}
