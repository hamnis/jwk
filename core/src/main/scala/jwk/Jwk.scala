package jwk

import java.security._
import java.security.interfaces._

case class JwkSet(keys: Set[Jwk]) {
  def get(id: Jwk.Id): Option[Jwk] =
    keys.find(_.id == id)
}

sealed trait Jwk extends Product with Serializable {
  def id: Jwk.Id
}

object Jwk {
  case class Id(value: String) extends AnyVal

  sealed trait JWKPrivateKey[A <: PrivateKey] extends Jwk {
    def privateKey: Option[A]
  }

  sealed trait JWKPublicKey[A <: PublicKey] extends Jwk {
    def publicKey: A
    def use: Option[Use]
    def x509: Option[X509]
  }

  case class RSA(
      id: Id,
      alg: Option[RSA.Algorithm],
      publicKey: RSAPublicKey,
      privateKey: Option[RSAPrivateKey],
      use: Option[Use],
      x509: Option[X509]
  ) extends JWKPublicKey[RSAPublicKey]
      with JWKPrivateKey[RSAPrivateKey]

  object RSA {
    sealed abstract class Algorithm(val jose: String) extends Product with Serializable

    object Algorithm {
      final case object RS256 extends Algorithm("RS256")
      final case object RS384 extends Algorithm("RS384")
      final case object RS512 extends Algorithm("RS512")
      val values: Set[Algorithm] = Set(RS256, RS384, RS512)
    }
  }

  case class EC(
      id: Id,
      curve: EC.Curve,
      publicKey: ECPublicKey,
      privateKey: Option[ECPrivateKey],
      use: Option[Use],
      x509: Option[X509]
  ) extends JWKPublicKey[ECPublicKey]
      with JWKPrivateKey[ECPrivateKey]

  object EC {
    sealed abstract class Curve(val jose: String, val jce: String) extends Product with Serializable

    object Curve {
      final case object P256 extends Curve("P-256", "secp256r1")
      final case object P384 extends Curve("P-384", "secp384r1")
      final case object P512 extends Curve("P-512", "secp512r1")

      val values: Set[Curve] = Set(P256, P384, P512)
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
