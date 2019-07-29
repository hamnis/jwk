package jwk

import java.security._
import java.security.interfaces._
import java.security.spec._

import io.circe.Decoder
import java.net.URI
import java.util.Base64

import cats.MonadError

sealed trait KeyType extends Product with Serializable

object KeyType {
  final case object EC  extends KeyType
  final case object RSA extends KeyType
}

sealed trait Use extends Product with Serializable

object Use {
  final case object Signature              extends Use
  final case object Encryption             extends Use
  final case class Extension(name: String) extends Use
}

sealed trait JWKPublicKey[A <: PublicKey] extends Product with Serializable {
  def id: String

  def publicKey[F[_]](implicit M: MonadError[F, Throwable]): F[A]

  def use: Option[Use]

  val x5u: Option[URI]
  val x5t: Option[String]
}

object JWKPublicKey {

  case class RSA(id: String,
                 alg: RSA.Algorithm,
                 exponent: BigInt,
                 modulus: BigInt,
                 use: Option[Use],
                 x5u: Option[URI],
                 x5t: Option[String])
      extends JWKPublicKey[RSAPublicKey] {
    def publicKey[F[_]](implicit M: MonadError[F, Throwable]): F[RSAPublicKey] = M.catchNonFatal {
      val kf = KeyFactory.getInstance("RSA")
      kf.generatePublic(new RSAPublicKeySpec(modulus.bigInteger, exponent.bigInteger)).asInstanceOf[RSAPublicKey]
    }
  }

  object RSA {
    sealed abstract class Algorithm(val jose: String) extends Product with Serializable

    object Algorithm {
      final case object RS256 extends Algorithm("RS256")
      final case object RS384 extends Algorithm("RS384")
      final case object RS512 extends Algorithm("RS512")
      val values: Set[Algorithm] = Set(RS256, RS384, RS512)
    }
  }

  case class EC(id: String, curve: EC.Algorithm, x: BigInt, y: BigInt, use: Option[Use], x5u: Option[URI], x5t: Option[String])
      extends JWKPublicKey[ECPublicKey] {
    def publicKey[F[_]](implicit M: MonadError[F, Throwable]): F[ECPublicKey] = M.catchNonFatal {
      val kf    = KeyFactory.getInstance("EC")
      val point = new ECPoint(x.bigInteger, y.bigInteger)
      kf.generatePublic(new ECPublicKeySpec(point, curve.spec)).asInstanceOf[ECPublicKey]
    }
  }

  object EC {
    sealed abstract class Algorithm(val jose: String, jce: String) extends Product with Serializable {
      private[jwk] def spec: ECParameterSpec = {
        val params = AlgorithmParameters.getInstance("EC")
        params.init(new ECGenParameterSpec(jce))
        params.getParameterSpec(classOf[ECParameterSpec])
      }
    }

    object Algorithm {
      final case object P256 extends Algorithm("P-256", "secp256r1")
      final case object P384 extends Algorithm("P-384", "secp384r1")
      final case object P512 extends Algorithm("P-512", "secp512r1")

      val values: Set[Algorithm] = Set(P256, P384, P512)
    }

  }

  implicit val uriDecoder: Decoder[URI] = Decoder[String].map(URI.create)

  implicit val keyTypeDecoder: Decoder[KeyType] = Decoder[String].emap {
    case "EC"  => Right(KeyType.EC)
    case "RSA" => Right(KeyType.RSA)
    case kt    => Left(s"$kt is not supported")
  }

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
      _        <- c.downField("kty").as[KeyType](keyTypeDecoder.ensure(_ == KeyType.RSA, "Not an RSA key type"))
      id       <- c.downField("kid").as[String]
      alg      <- c.downField("alg").as[RSA.Algorithm]
      use      <- c.downField("use").as[Option[Use]]
      exponent <- c.downField("e").as[BigInt]
      modulus  <- c.downField("n").as[BigInt]
      x5u      <- c.downField("x5u").as[Option[URI]]
      x5t      <- c.downField("x5t").as[Option[String]]
    } yield RSA(id, alg, exponent, modulus, use, x5u, x5t)
  }

  implicit val ecPublicKeyDecoder: Decoder[EC] = Decoder.instance { c =>
    for {
      _     <- c.downField("kty").as[KeyType](keyTypeDecoder.ensure(_ == KeyType.EC, "Not an EC key type"))
      id    <- c.downField("kid").as[String]
      curve <- c.downField("crv").as[EC.Algorithm]
      use   <- c.downField("use").as[Option[Use]]
      x     <- c.downField("x").as[BigInt]
      y     <- c.downField("y").as[BigInt]
      x5u   <- c.downField("x5u").as[Option[URI]]
      x5t   <- c.downField("x5t").as[Option[String]]
    } yield EC(id, curve, x, y, use, x5u, x5t)
  }

  implicit val publicKeyDecoder: Decoder[JWKPublicKey[_]] = {
    import cats.syntax.functor._
    rsaPublicKeyDecoder.widen[JWKPublicKey[_]].or(ecPublicKeyDecoder.widen[JWKPublicKey[_]])
  }
}
