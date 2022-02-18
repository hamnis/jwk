overridePublishSignedSettings

publishTo := {
  if (isSnapshot.value) {
    Some(Opts.resolver.sonatypeSnapshots)
  } else {
    Some(Opts.resolver.sonatypeStaging)
  }
}

pomIncludeRepository := { x =>
  false
}

packageOptions += {
  val title  = name.value
  val ver    = version.value
  val vendor = organization.value

  Package.ManifestAttributes(
    "Created-By"               -> "Scala Build Tool",
    "Built-By"                 -> System.getProperty("user.name"),
    "Build-Jdk"                -> System.getProperty("java.version"),
    "Specification-Title"      -> title,
    "Specification-Version"    -> ver,
    "Specification-Vendor"     -> vendor,
    "Implementation-Title"     -> title,
    "Implementation-Version"   -> ver,
    "Implementation-Vendor-Id" -> vendor,
    "Implementation-Vendor"    -> vendor,
  )
}

credentials ++= Seq(
  Credentials(Path.userHome / ".sbt" / ".credentials")
)

homepage := Some(url("https://github.com/hamnis/jwk"))

startYear := Some(2019)

licenses := Seq(
  License.Apache2
)

publishMavenStyle := true

Test / publishArtifact := false

pomIncludeRepository := { _ =>
  false
}

releaseCrossBuild := true

releasePublishArtifactsAction := PgpKeys.publishSigned.value

scmInfo := Some(
  ScmInfo(
    new URL("https://github.com/hamnis/jwk"),
    "scm:git:git@github.com:hamnis/jwk.git",
    Some("scm:git:git@github.com:hamnis/jwk.git"),
  )
)

developers ++= List(
  Developer(
    "hamnis",
    "Erlend Hamnaberg",
    "erlend@hamnaberg.net",
    new URL("http://twitter.com/hamnis"),
  )
)
