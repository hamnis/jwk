inThisBuild(
  Seq(
    crossScalaVersions := Seq("2.13.8", "3.1.1"),
    scalaVersion       := crossScalaVersions.value.head,
    scalacOptions ++= Seq(
      "-feature",
      "-language:higherKinds",
      "-language:implicitConversions",
      "-unchecked",
      "-deprecation",
    ),
  )
)

val core = project.settings(
  libraryDependencies ++= Seq(
    "org.scodec"    %% "scodec-bits"  % "1.1.30",
    "io.circe"      %% "circe-core"   % "0.14.1",
    "org.typelevel" %% "cats-effect"  % "3.3.5",
    "io.circe"      %% "circe-parser" % "0.14.1",
    "org.scalatest" %% "scalatest"    % "3.2.11" % Test,
  )
)

val http4s = project
  .dependsOn(core)
  .settings(
    libraryDependencies ++= Seq(
      "org.http4s" %% "http4s-client" % "0.23.9",
      "org.http4s" %% "http4s-circe"  % "0.23.9",
    )
  )

val sttp = project
  .dependsOn(core)
  .settings(
    libraryDependencies ++= Seq(
      "com.softwaremill.sttp.client3" %% "core" % "3.5.0"
    )
  )

val jwk = project.in(file(".")).aggregate(core, http4s)
