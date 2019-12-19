package jwk

import java.security.SecureRandom

import cats.effect.{Blocker, ContextShift, Sync}

trait Entropy[F[_]] {
  def source: F[SecureRandom]
}

object Entropy {
  def secure[F[_]: Sync: ContextShift](blocker: Blocker): F[Entropy[F]] = blocker.delay {
    val cached = SecureRandom.getInstanceStrong
    new Entropy[F] {
      override def source: F[SecureRandom] = {
        Sync[F].pure(cached)
      }
    }
  }
  def default[F[_]: Sync: ContextShift](blocker: Blocker, seedSize: Int = 128): Entropy[F] = new Entropy[F] {
    override def source: F[SecureRandom] = {
      blocker.delay {
        val rnd = new SecureRandom()
        rnd.generateSeed(seedSize)
        rnd
      }
    }
  }
}
