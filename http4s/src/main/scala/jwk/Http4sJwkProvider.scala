package jwk

import java.net.URI

import cats.effect.Sync
import jwk.circe._
import org.http4s.EntityDecoder
import org.http4s.client.Client

class Http4sJwkProvider[F[_]: Sync] private(client: Client[F]) extends JwkProvider[F] {
  implicit val decoder: EntityDecoder[F, JwkSet] = org.http4s.circe.jsonOf[F, JwkSet]

  override def load(uri: URI): F[JwkSet] = {
    client.expect[JwkSet](uri.toString)
  }
}

object Http4sJwkProvider {
  def apply[F[_]: Sync](client: Client[F]): Http4sJwkProvider[F] =
    new Http4sJwkProvider[F](client)
}
