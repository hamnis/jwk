package jwk

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.net.URI
import java.security.{AlgorithmParameters, KeyFactory}
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.interfaces.{ECPrivateKey, ECPublicKey, RSAPrivateCrtKey, RSAPublicKey}
import java.security.spec.{
  ECGenParameterSpec,
  ECParameterSpec,
  ECPoint,
  ECPrivateKeySpec,
  ECPublicKeySpec,
  RSAPrivateCrtKeySpec,
  RSAPublicKeySpec
}

import io.circe._
import io.circe.syntax._
import jwk.Jwk._
import cats.implicits._
import javax.crypto.spec.SecretKeySpec
import scodec.bits.{Bases, ByteVector}

import scala.util.Try

object circe {
  implicit val byteVectorDecoder: Codec[ByteVector] =
    Codec.from(
      Decoder[String].emap(
        s => ByteVector.fromBase64Descriptive(s, Bases.Alphabets.Base64Url).orElse(ByteVector.fromBase64Descriptive(s))
      ),
      Encoder[String].contramap(_.toBase64(Bases.Alphabets.Base64Url))
    )

  implicit val uriDecoder: Codec[URI] = Codec.from(Decoder[String].map(URI.create), Encoder[String].contramap(_.toString))
  implicit val BigIntBigEndianDecoder: Codec[BigInteger] =
    Codec.from(
      Decoder[ByteVector].map(n => BigInt(1, n.toArray).bigInteger),
      Encoder[ByteVector].contramap(bi => ByteVector.apply(bi.toByteArray))
    )
  implicit val rsaAlgDecoder: Codec[RSA.Algorithm] = Codec.from(
    Decoder[String].emap { alg =>
      RSA.Algorithm.values.find(_.jose == alg).toRight(s"$alg is not supported")
    },
    Encoder[String].contramap(_.jose)
  )
  implicit val hmacAlgDecoder: Codec[HMac.Algorithm] =
    Codec.from(Decoder[String].emap { alg =>
      HMac.Algorithm.values.find(_.jose == alg).toRight(s"$alg is not supported")
    }, Encoder[String].contramap(_.jose))

  def tryDecode[A](c: HCursor, tried: Try[A]): Decoder.Result[A] =
    tried.toEither.leftMap(e => DecodingFailure.fromThrowable(e, c.history))

  implicit val useDecoder: Decoder[Use] = Decoder[String].map {
    case "sig" => Use.Signature
    case "enc" => Use.Encryption
    case e     => Use.Extension(e)
  }

  implicit val useEncoder: Encoder[Use] = Encoder[String].contramap {
    case Use.Signature      => "sig"
    case Use.Encryption     => "enc"
    case Use.Extension(ext) => ext
  }

  implicit val keyOpCodec: Codec[KeyOp] = Codec.from(
    Decoder[String].map(KeyOp.apply),
    Encoder[String].contramap(_.value)
  )

  implicit val curveDecoder: Codec[EllipticCurve.Curve] = Codec.from(Decoder[String].emap { alg =>
    EllipticCurve.Curve.values.find(_.jose == alg).toRight(s"$alg is not supported")
  }, Encoder[String].contramap(_.jose))

  implicit val x509CertificateDecoder: Decoder[X509Certificate] =
    Decoder[ByteVector].emapTry { s =>
      Try {
        val factory = CertificateFactory.getInstance("X.509")
        factory.generateCertificate(new ByteArrayInputStream(s.toArray)).asInstanceOf[X509Certificate]
      }
    }
  implicit val x509CertificateEncoder: Encoder[X509Certificate] = {
    Encoder[String].contramap(c => ByteVector(c.getEncoded).toBase64)
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

  implicit val x509Encoder: Encoder[X509] = Encoder.instance {
    case X509Chain(x5c, sha1, sha256) =>
      Json.obj(
        "x5c" := x5c,
        "x5t" := sha1,
        "x5t#S256" := sha256
      )
    case X509Url(url, sha1, sha256) =>
      Json.obj(
        "x5u" := url,
        "x5t" := sha1,
        "x5t#S256" := sha256
      )
  }

  private def rsa(c: HCursor): Decoder.Result[(RSAPublicKey, Option[RSAPrivateCrtKey])] = {
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
                   .map(factory.generatePrivate(_).asInstanceOf[RSAPrivateCrtKey])
               }
             )
    } yield (public, priv)
  }

  implicit val rsaDecoder: Decoder[RSA] = Decoder.instance { c =>
    for {
      _           <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "RSA", "Not an RSA key type"))
      id          <- c.downField("kid").as[String].map(Id.apply)
      alg         <- c.downField("alg").as[Option[RSA.Algorithm]]
      use         <- c.downField("use").as[Option[Use]]
      keyOps      <- c.downField("key_ops").as[Option[KeyOp]]
      rsaTuple    <- rsa(c)
      (pub, priv) = rsaTuple
      x509        <- x509Decoder(c)
    } yield RSA(id, alg, pub, priv, use, x509, keyOps)
  }

  implicit val rsaEncoder: Encoder[RSA] = Encoder.instance { rsa =>
    val base = Json.obj(
      "kty" := "RSA",
      "kid" := rsa.id.value,
      "alg" := rsa.alg,
      "use" := rsa.use,
      "key_ops" := rsa.keyOps,
      "n" := rsa.publicKey.getModulus,
      "e" := rsa.publicKey.getPublicExponent
    )

    val privateKey = rsa.privateKey
      .map(
        priv =>
          Json.obj(
            "d" := priv.getPrivateExponent,
            "p" := priv.getPrimeP,
            "q" := priv.getPrimeQ,
            "dp" := priv.getPrimeExponentP,
            "dq" := priv.getPrimeExponentQ,
            "qi" := priv.getCrtCoefficient
          )
      )
      .getOrElse(Json.obj())

    val x509 = rsa.x509.asJson

    x509.deepMerge(privateKey.deepMerge(base))
  }

  implicit val ecEncoder: Encoder[EllipticCurve] = Encoder.instance { ec =>
    val base = Json.obj(
      "kty" := "EC",
      "kid" := ec.id.value,
      "crv" := ec.curve.jose,
      "use" := ec.use,
      "key_ops" := ec.keyOps,
      "x" := ec.publicKey.getW.getAffineX,
      "y" := ec.publicKey.getW.getAffineY,
      "d" := ec.privateKey.map(_.getS)
    )
    val x509 = ec.x509.asJson
    x509.deepMerge(base)
  }

  implicit val ecDecoder: Decoder[EllipticCurve] = Decoder.instance { c =>
    for {
      _      <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "EC", "Not an EC key type"))
      id     <- c.downField("kid").as[String].map(Id.apply)
      curve  <- c.downField("crv").as[EllipticCurve.Curve]
      use    <- c.downField("use").as[Option[Use]]
      keyOps <- c.downField("key_ops").as[Option[KeyOp]]
      ec     <- ec(c, curve)
      x509   <- x509Decoder(c)
    } yield EllipticCurve(id, curve, ec._1, ec._2, use, x509, keyOps)
  }

  def ec(c: HCursor, curve: EllipticCurve.Curve): Decoder.Result[(ECPublicKey, Option[ECPrivateKey])] = {
    for {
      x     <- c.downField("x").as[BigInteger]
      y     <- c.downField("y").as[BigInteger]
      d     <- c.downField("d").as[Option[BigInteger]]
      point <- tryDecode(c, Try { new ECPoint(x, y) })
      kf    <- tryDecode(c, Try { KeyFactory.getInstance("EC") })
      spec <- tryDecode(c, Try {
               val params = AlgorithmParameters.getInstance("EC")
               params.init(new ECGenParameterSpec(curve.jce))
               params.getParameterSpec(classOf[ECParameterSpec])
             })
      pk <- tryDecode(c, Try { kf.generatePublic(new ECPublicKeySpec(point, spec)).asInstanceOf[ECPublicKey] })
      priv <- tryDecode(c, Try {
               d.map(priv => kf.generatePrivate(new ECPrivateKeySpec(priv, spec)).asInstanceOf[ECPrivateKey])
             })
    } yield (pk, priv)
  }

  implicit val hmacDecoder: Decoder[HMac] = Decoder.instance { c =>
    for {
      _          <- c.downField("kty").as(Decoder.decodeString.ensure(_ == "oct", "Not an 'oct' key type"))
      id         <- c.downField("kid").as[String].map(Id.apply)
      alg        <- c.downField("alg").as[HMac.Algorithm]
      use        <- c.downField("use").as[Option[Use]]
      key        <- c.downField("k").as[ByteVector]
      keyOps     <- c.downField("key_ops").as[Option[KeyOp]]
      decodedKey <- tryDecode(c, Try { new SecretKeySpec(key.toArray, alg.jce) })
    } yield HMac(id, alg, decodedKey, use, keyOps)
  }

  implicit val hmacEncoder: Encoder[HMac] = Encoder.instance { hmac =>
    Json.obj(
      "kty" := "oct",
      "kid" := hmac.id.value,
      "alg" := hmac.algorithm.jose,
      "use" := hmac.use,
      "key_ops" := hmac.keyOps,
      "k" := ByteVector(hmac.key.getEncoded)
    )
  }

  implicit val jwkDecoder: Decoder[Jwk] = {
    rsaDecoder.widen[Jwk].or(ecDecoder.widen[Jwk]).or(hmacDecoder.widen[Jwk])
  }

  implicit val jwkEncoder: Encoder[Jwk] = Encoder.instance {
    case rsa: RSA          => rsa.asJson
    case ec: EllipticCurve => ec.asJson
    case hmac: HMac        => hmac.asJson
  }

  implicit val jwkSetDecoder: Decoder[JwkSet] = Decoder.instance(c => c.downField("keys").as[Set[Jwk]].map(JwkSet.apply))
  implicit val jwkSetEncoder: Encoder[JwkSet] = Encoder.instance(
    set =>
      Json.obj(
        "keys" := set.keys.asJson
      )
  )
}
