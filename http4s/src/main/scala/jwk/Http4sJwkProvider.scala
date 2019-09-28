package jwk

import java.net.URI

import org.http4s.EntityDecoder
import org.http4s.client.Client

class Http4sJwkProvider[F[_]](client: Client[F])(implicit decoder: EntityDecoder[F, JwkSet]) extends JwkProvider[F] {
  override def load(uri: URI): F[JwkSet] = {
    client.expect[JwkSet](uri.toString)
  }
}
