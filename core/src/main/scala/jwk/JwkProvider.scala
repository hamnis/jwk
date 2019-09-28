package jwk

import java.net.URI

import cats.data.OptionT

trait JwkProvider[F[_]] {
  def load(uri: URI): F[JwkSet]
  //def get(id: Jwk.Id): OptionT[F, Jwk]
}
