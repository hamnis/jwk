package jwk

import java.net.URI

trait JwkProvider[F[_]] {
  def load(uri: URI): F[JwkSet]
}
