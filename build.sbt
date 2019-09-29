inThisBuild(
  Seq(
    scalaVersion := "2.12.10",
    scalacOptions ++= Seq(
      "-Ypartial-unification",
      "-feature",
      "-language:higherKinds",
      "-language:implicitConversions",
      "-unchecked",
      "-deprecation"
    )
  )
)

val core = project.settings(
  libraryDependencies ++= Seq(
    "org.scodec"    %% "scodec-bits"  % "1.1.12",
    "io.circe"      %% "circe-core"   % "0.12.1",
    "io.circe"      %% "circe-parser" % "0.12.1" % Test,
    "org.scalatest" %% "scalatest"    % "3.0.8" % Test
  )
)

val http4s = project
  .dependsOn(core)
  .settings(
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-client" % "0.21.0-M5",
      "org.http4s" %% "http4s-circe"  % "0.21.0-M5"
    )
  )

val sttp = project
  .dependsOn(core)
  .settings(
    libraryDependencies ++= Seq(
      "com.softwaremill.sttp" %% "core"         % "1.6.7",
      "io.circe"              %% "circe-parser" % "0.12.1"
    )
  )

val jwk = project.in(file(".")).aggregate(core, http4s)
