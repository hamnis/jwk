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
}
