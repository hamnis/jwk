lazy val commonSettings = Seq(
  organization       := "net.hamnaberg.jwk",
  crossScalaVersions := Seq("2.13.8", "3.1.1"),
  scalaVersion       := crossScalaVersions.value.head,
  scalacOptions ++= Seq(
    "-feature",
    "-language:higherKinds",
    "-language:implicitConversions",
    "-unchecked",
    "-deprecation",
  ),
  releasePublishArtifactsAction := PgpKeys.publishSigned.value,
  ThisBuild / versionScheme     := Some("early-semver"),
  publishTo := {
    if (isSnapshot.value) {
      Some(Opts.resolver.sonatypeSnapshots)
    } else {
      Some(Opts.resolver.sonatypeStaging)
    }
  },
  pomIncludeRepository := { x =>
    false
  },
  Test / publishArtifact := false,
  pomIncludeRepository := { _ =>
    false
  },
  homepage := Some(url("https://github.com/hamnis/jwk")),
  startYear := Some(2019),
  licenses += License.Apache2,
  scmInfo := Some(
    ScmInfo(
      new URL("https://github.com/hamnis/jwk"),
      "scm:git:git@github.com:hamnis/jwk.git",
      Some("scm:git:git@github.com:hamnis/jwk.git"),
    )
  ),
  developers ++=
    List(
      Developer(
        "hamnis",
        "Erlend Hamnaberg",
        "erlend@hamnaberg.net",
        new URL("http://twitter.com/hamnis"),
      )
    ),
  credentials += Credentials(Path.userHome / ".sbt" / ".credentials"),
)

val core = project
  .settings(commonSettings)
  .settings(
    name := "jwk-core",
    libraryDependencies ++= Seq(
      "org.scodec"    %% "scodec-bits"  % "1.1.30",
      "io.circe"      %% "circe-core"   % "0.14.1",
      "org.typelevel" %% "cats-effect"  % "3.3.5",
      "io.circe"      %% "circe-parser" % "0.14.1",
      "org.scalatest" %% "scalatest"    % "3.2.11" % Test,
    ),
  )

val http4s = project
  .dependsOn(core)
  .settings(commonSettings)
  .settings(
    name := "jwk-http4s",
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-client" % "0.23.9",
      "org.http4s" %% "http4s-circe"  % "0.23.9",
    ),
  )

val sttp = project
  .dependsOn(core)
  .settings(commonSettings)
  .settings(
    name := "jwk-sttp3",
    libraryDependencies ++= Seq(
      "com.softwaremill.sttp.client3" %% "core" % "3.5.0"
    ),
  )

val jwk = project
  .in(file("."))
  .aggregate(core, http4s, sttp)
  .settings(commonSettings)
  .settings(
    publish                := false,
    publishArtifact        := false,
    Test / publishArtifact := false,
    releaseVersionBump     := sbtrelease.Version.Bump.Minor,
    releaseCrossBuild      := true,
  )
