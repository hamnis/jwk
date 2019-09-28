package jwk

import java.security._
import java.security.interfaces._
import java.security.spec._

case class JwkSet(keys: Set[Jwk]) {
  def get(id: Jwk.Id): Option[Jwk] =
    keys.find(_.id == id)
}

sealed trait Jwk {
  def id: Jwk.Id
}

object Jwk {
  case class Id(value: String) extends AnyVal

  sealed trait JWKPublicKey[A <: PublicKey] extends Jwk with Product with Serializable {
    def publicKey: A
    def use: Option[Use]
    def x509: Option[X509]
  }

  object JWKPublicKey {

    case class RSA(
        id: Id,
        alg: Option[RSA.Algorithm],
        publicKey: RSAPublicKey,
        use: Option[Use],
        x509: Option[X509]
    ) extends JWKPublicKey[RSAPublicKey]

    object RSA {
      sealed abstract class Algorithm(val jose: String) extends Product with Serializable

      object Algorithm {
        final case object RS256 extends Algorithm("RS256")
        final case object RS384 extends Algorithm("RS384")
        final case object RS512 extends Algorithm("RS512")
        val values: Set[Algorithm] = Set(RS256, RS384, RS512)
      }

      def publicKey(modulus: BigInt, exponent: BigInt): Either[Throwable, RSAPublicKey] =
        scala.util.control.Exception.nonFatalCatch.either {
          val kf = KeyFactory.getInstance("RSA")
          kf.generatePublic(new RSAPublicKeySpec(modulus.bigInteger, exponent.bigInteger)).asInstanceOf[RSAPublicKey]
        }
    }

    case class EC(id: Id, alg: EC.Algorithm, publicKey: ECPublicKey, use: Option[Use], x509: Option[X509])
        extends JWKPublicKey[ECPublicKey]

    object EC {
      sealed abstract class Algorithm(val jose: String, jce: String) extends Product with Serializable {
        private[jwk] lazy val spec: ECParameterSpec = {
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

      def publicKey(x: BigInt, y: BigInt, curve: Algorithm): Either[Throwable, ECPublicKey] =
        scala.util.control.Exception.nonFatalCatch.either {
          val kf    = KeyFactory.getInstance("EC")
          val point = new ECPoint(x.bigInteger, y.bigInteger)
          kf.generatePublic(new ECPublicKeySpec(point, curve.spec)).asInstanceOf[ECPublicKey]
        }
    }
  }
}

sealed trait Use extends Product with Serializable

object Use {
  final case object Signature              extends Use
  final case object Encryption             extends Use
  final case class Extension(name: String) extends Use
}

sealed trait KeyOps extends Product with Serializable

object KeyOps {
  final case object Sign               extends KeyOps
  final case object Verify             extends KeyOps
  final case object Encrypt            extends KeyOps
  final case object Decrypt            extends KeyOps
  final case object WrapKey            extends KeyOps
  final case object UnwrapKey          extends KeyOps
  final case object DeriveKey          extends KeyOps
  final case object DeriveBits         extends KeyOps
  final case class Other(name: String) extends KeyOps
}
