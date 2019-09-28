package jwk

import cats.data.OptionT

trait JwkProvider[F[_]] {
  def get(id: Jwk.Id): OptionT[F, Jwk]
}
