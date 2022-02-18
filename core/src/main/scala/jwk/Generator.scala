package jwk

import java.security.interfaces.{ECPrivateKey, ECPublicKey, RSAPrivateCrtKey, RSAPublicKey}
import java.security.spec.{ECGenParameterSpec, ECParameterSpec}
import java.security.{AlgorithmParameters, KeyPairGenerator}

import cats.effect.Sync
import cats.syntax.flatMap._
import cats.syntax.functor._

object Generator {
  object RSA {
    def generate[F[_]: Sync](id: Jwk.Id, alg: Option[Jwk.RSA.Algorithm] = None, use: Option[Use] = None, keySize: Int = 4096)(
        implicit entropy: Entropy[F]
    ): F[Jwk.RSA] =
      for {
        random <- entropy.source
        keypair <- Sync[F].delay {
          val gen = KeyPairGenerator.getInstance("RSA")
          gen.initialize(keySize, random)
          gen.generateKeyPair()
        }
      } yield Jwk.RSA(
        id,
        alg,
        keypair.getPublic.asInstanceOf[RSAPublicKey],
        Some(keypair.getPrivate.asInstanceOf[RSAPrivateCrtKey]),
        use,
        None,
        None,
      )
  }

  object EC {
    def generate[F[_]: Sync](id: Jwk.Id, curve: Jwk.EllipticCurve.Curve, use: Option[Use] = None)(implicit
        entropy: Entropy[F]
    ) =
      for {
        random <- entropy.source
        keypair <- Sync[F].delay {
          val gen = KeyPairGenerator.getInstance("EC")
          val alg = AlgorithmParameters.getInstance("EC")
          alg.init(new ECGenParameterSpec(curve.jce))
          val spec = alg.getParameterSpec(classOf[ECParameterSpec])
          gen.initialize(spec, random)
          gen.generateKeyPair()
        }
        // cert <- genX509(keypair)
      } yield Jwk.EllipticCurve(
        id,
        curve,
        keypair.getPublic.asInstanceOf[ECPublicKey],
        Some(keypair.getPrivate.asInstanceOf[ECPrivateKey]),
        use,
        None,
        None,
      )

  }
}
