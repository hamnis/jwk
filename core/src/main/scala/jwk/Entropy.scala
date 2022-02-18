package jwk

import java.security.SecureRandom

import cats.effect.Sync

trait Entropy[F[_]] {
  def source: F[SecureRandom]
}

object Entropy {
  def secure[F[_]: Sync]: F[Entropy[F]] = Sync[F].blocking {
    val cached = SecureRandom.getInstanceStrong
    new Entropy[F] {
      override def source: F[SecureRandom] = {
        Sync[F].pure(cached)
      }
    }
  }
  def default[F[_]: Sync](seedSize: Int = 128): Entropy[F] = new Entropy[F] {
    override def source: F[SecureRandom] = {
      Sync[F].blocking {
        val rnd = new SecureRandom()
        rnd.generateSeed(seedSize)
        rnd
      }
    }
  }
}
